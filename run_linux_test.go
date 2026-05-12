//go:build linux

package main

import (
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func TestSplitWGAddresses(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			// Regression: gateway-emitted wg-quick conf carries both
			// v4 and v6 in a single `Address =` line. Passing the
			// whole comma-joined string to `ip addr add` fails with
			// "any valid prefix is expected rather than ...".
			name: "dual stack",
			in:   "10.55.0.5/32, fd77::5/128",
			want: []string{"10.55.0.5/32", "fd77::5/128"},
		},
		{
			name: "dual stack no space after comma",
			in:   "10.55.0.5/32,fd77::5/128",
			want: []string{"10.55.0.5/32", "fd77::5/128"},
		},
		{
			name: "v4 only",
			in:   "10.55.0.5/32",
			want: []string{"10.55.0.5/32"},
		},
		{
			name: "v6 only",
			in:   "fd77::5/128",
			want: []string{"fd77::5/128"},
		},
		{
			name: "missing prefix v4 defaults to /32",
			in:   "10.55.0.5",
			want: []string{"10.55.0.5/32"},
		},
		{
			name: "missing prefix v6 defaults to /128",
			in:   "fd77::5",
			want: []string{"fd77::5/128"},
		},
		{
			name: "extra whitespace and empty parts",
			in:   "  10.55.0.5/32 ,, fd77::5/128 ,",
			want: []string{"10.55.0.5/32", "fd77::5/128"},
		},
		{
			name: "empty input",
			in:   "",
			want: nil,
		},
		{
			name: "only whitespace and commas",
			in:   " , , ",
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitWGAddresses(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("splitWGAddresses(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

// TestEphemeralCacheRoundTrip persists an entry, reads it back, and
// confirms the marshalled form survives. Guards against a future
// refactor silently changing the on-disk schema (which would force
// every host's `clawpatrol run` to mint a fresh keypair on upgrade).
func TestEphemeralCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wg-ephemeral.json")
	in := &ephemeralCache{
		GatewayURL: "https://gw.example",
		PrivateKey: "aGVsbG8td29ybGQ=", // arbitrary base64
		PublicHex:  "abcdef0123456789",
		IP:         "10.55.0.42",
		IP6:        "fd77::42",
	}
	writeEphemeralCache(path, in)
	out, err := readEphemeralCache(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Fatalf("round trip mismatch:\n got: %#v\nwant: %#v", out, in)
	}
}

// TestEphemeralCacheRejectsIncomplete covers the "client wrote a
// half-baked cache and crashed" path — read must reject so the next
// run mints a fresh keypair rather than POSTing garbage.
func TestEphemeralCacheRejectsIncomplete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wg-ephemeral.json")
	writeEphemeralCache(path, &ephemeralCache{
		GatewayURL: "https://gw.example",
		// PrivateKey + PublicHex missing.
		IP: "10.55.0.42",
	})
	if _, err := readEphemeralCache(path); err == nil {
		t.Fatal("read accepted cache with no keypair")
	}
}

// TestEphemeralLockSerializesConcurrentRuns confirms two siblings
// can't both hold the lock at once. The second goroutine must block
// until the first releases — this is what guarantees the second run
// reads the freshly-written cache instead of racing to mint its own.
func TestEphemeralLockSerializesConcurrentRuns(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "wg-ephemeral.json")

	unlock1, err := acquireEphemeralLock(cachePath)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}

	gotSecond := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		unlock2, err := acquireEphemeralLock(cachePath)
		if err != nil {
			t.Errorf("second lock: %v", err)
			return
		}
		close(gotSecond)
		unlock2()
	}()

	// The lock is process-wide on Linux (flock); the second
	// goroutine should block while we hold it.
	select {
	case <-gotSecond:
		t.Fatal("second lock acquired while first still held")
	default:
	}

	unlock1()
	wg.Wait()
	select {
	case <-gotSecond:
	default:
		t.Fatal("second lock never acquired after first released")
	}
}
