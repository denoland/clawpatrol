//go:build linux

package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestParseProcNetIPHex covers the endian-juggling for the local_address
// column in /proc/net/tcp{,6}. The expected outputs are the canonical
// network-order bytes — the host endianness of the running test should
// not affect them.
func TestParseProcNetIPHex(t *testing.T) {
	cases := []struct {
		name string
		// hex string as emitted by the kernel on a little-endian host
		// (the only realistic clawpatrol target); parseProcNetIPHex
		// adapts via NativeEndian and produces the same network-order
		// bytes regardless of host.
		hexLE string
		want  net.IP
	}{
		{"v4 loopback", "0100007F", net.IPv4(127, 0, 0, 1).To4()},
		{"v4 any", "00000000", net.IPv4(0, 0, 0, 0).To4()},
		{"v4 1.2.3.4", "04030201", net.IPv4(1, 2, 3, 4).To4()},
		{"v6 any", "00000000000000000000000000000000", net.ParseIP("::")},
		{"v6 loopback", "00000000000000000000000001000000", net.ParseIP("::1")},
		{"v6 v4-mapped 127.0.0.1", "0000000000000000FFFF00000100007F", net.ParseIP("::ffff:127.0.0.1")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The test only matches the canonical LE-host behaviour
			// because that's what the kernel emits on amd64/arm64.
			got, err := parseProcNetIPHex(tc.hexLE)
			if err != nil {
				t.Fatalf("parseProcNetIPHex(%q): %v", tc.hexLE, err)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("parseProcNetIPHex(%q) = %s, want %s", tc.hexLE, got, tc.want)
			}
		})
	}
}

// TestParseProcNetIPHexBadInput exercises the input validation.
func TestParseProcNetIPHexBadInput(t *testing.T) {
	cases := []string{
		"",
		"010",                                  // wrong length
		"GGGGGGGG",                             // bad hex
		"0100007F0100007F",                     // wrong length (16)
		"000000000000000000000000010000000000", // wrong length (36)
	}
	for _, s := range cases {
		if _, err := parseProcNetIPHex(s); err == nil {
			t.Fatalf("parseProcNetIPHex(%q) accepted bad input", s)
		}
	}
}

// TestScanProcNetTcp synthesises a /proc/net/tcp file and verifies
// scanProcNetTCP finds the row by inode + state.
func TestScanProcNetTcp(t *testing.T) {
	dir := t.TempDir()
	v4 := filepath.Join(dir, "tcp")
	v6 := filepath.Join(dir, "tcp6")

	if err := os.WriteFile(v4, []byte(""+
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99001 1 0000000000000000 100 0 0 10 0\n"+
		"   1: 04030201:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99002 1 0000000000000000 100 0 0 10 0\n"+
		"   2: 0100007F:2710 0100007F:1234 01 00000000:00000000 00:00000000 00000000  1000        0 99003 1 0000000000000000 100 0 0 10 0\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(v6, []byte(""+
		"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99100 1 0000000000000000 100 0 0 10 0\n"+
		"   1: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99101 1 0000000000000000 100 0 0 10 0\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		path      string
		ipHexLen  int
		inode     uint64
		wantPort  uint16
		wantIP    net.IP
		wantFound bool
	}{
		{"v4 listen on 127.0.0.1:8080", v4, 8, 99001, 8080, net.IPv4(127, 0, 0, 1).To4(), true},
		{"v4 listen on 1.2.3.4:80", v4, 8, 99002, 80, net.IPv4(1, 2, 3, 4).To4(), true},
		{"v4 established skipped", v4, 8, 99003, 0, nil, false},
		{"v4 missing inode", v4, 8, 12345, 0, nil, false},
		{"v6 listen on :::8080", v6, 32, 99100, 8080, net.ParseIP("::"), true},
		{"v6 listen on ::1:80", v6, 32, 99101, 80, net.ParseIP("::1"), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			port, ip, ok, err := scanProcNetTCP(tc.path, tc.inode, tc.ipHexLen)
			if err != nil {
				t.Fatalf("scanProcNetTCP: %v", err)
			}
			if ok != tc.wantFound {
				t.Fatalf("found=%v, want %v", ok, tc.wantFound)
			}
			if !tc.wantFound {
				return
			}
			if port != tc.wantPort {
				t.Errorf("port=%d, want %d", port, tc.wantPort)
			}
			if !ip.Equal(tc.wantIP) {
				t.Errorf("ip=%s, want %s", ip, tc.wantIP)
			}
		})
	}
}

// TestMirrorBindScope verifies the host bind-address policy mirrors the
// agent's bind scope: loopback → loopback, otherwise unspecified, with
// a family-mismatch fallback to 127.0.0.1.
func TestMirrorBindScope(t *testing.T) {
	cases := []struct {
		family int
		inner  net.IP
		want   string
	}{
		{unix.AF_INET, net.IPv4(127, 0, 0, 1), "127.0.0.1"},
		{unix.AF_INET, net.IPv4(0, 0, 0, 0), "0.0.0.0"},
		{unix.AF_INET, net.IPv4(10, 0, 0, 5), "0.0.0.0"},
		{unix.AF_INET6, net.ParseIP("::1"), "::1"},
		{unix.AF_INET6, net.ParseIP("::"), "::"},
		{unix.AF_INET6, net.ParseIP("fd00::1"), "::"},
		{unix.AF_UNIX, net.IPv4(127, 0, 0, 1), "127.0.0.1"},
	}
	for _, tc := range cases {
		got := mirrorBindScope(tc.family, tc.inner)
		if got != tc.want {
			t.Errorf("mirrorBindScope(%d, %s) = %s, want %s",
				tc.family, tc.inner, got, tc.want)
		}
	}
}
