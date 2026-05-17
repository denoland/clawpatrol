//go:build linux

package main

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

const soOriginalDst = 80 // SO_ORIGINAL_DST, linux/in.h

// originalDst returns the pre-NAT destination of c when the connection
// was redirected by an iptables REDIRECT rule. Returns ok=false on
// non-Linux, for non-TCP conns, or when no NAT entry exists (direct
// connection — getsockopt returns ENOPROTOOPT or ENOENT).
func originalDst(c net.Conn) (ip string, port uint16, ok bool) {
	tc := unwrapTCPConn(c)
	if tc == nil {
		return "", 0, false
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return "", 0, false
	}
	var sa syscall.RawSockaddrInet4
	saLen := uint32(syscall.SizeofSockaddrInet4)
	var soErr error
	_ = raw.Control(func(fd uintptr) {
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.IPPROTO_IP,
			soOriginalDst,
			uintptr(unsafe.Pointer(&sa)),
			uintptr(unsafe.Pointer(&saLen)),
			0,
		)
		if errno != 0 {
			soErr = errno
		}
	})
	if soErr != nil {
		return "", 0, false
	}
	dstIP := net.IP(sa.Addr[:]).String()
	dstPort := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:])
	return dstIP, dstPort, true
}

// installExitNodeRedirect installs iptables PREROUTING REDIRECT rules so that
// traffic arriving via the Tailscale exit-node (tailscale0) on common service
// ports is redirected to the gateway's own listen port. This lets the accept
// loop's SO_ORIGINAL_DST fallback dispatch exit-node traffic exactly like the
// WireGuard promiscuous forwarder — no PROXY header needed.
//
// Idempotent: each rule is checked with -C before insertion. Failures are
// logged but not fatal; operators can install the rules manually if the
// process lacks CAP_NET_ADMIN.
func installExitNodeRedirect(listenPort int, extraPorts []string) {
	if listenPort == 0 {
		return
	}
	// Ensure ip_forward is on — exit-node forwarding silently breaks without it.
	// Write to sysctl.d for persistence across reboots.
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		log.Printf("exit-node redirect: ip_forward: %v", err)
	}
	const sysctlConf = "/etc/sysctl.d/99-clawpatrol-forward.conf"
	if _, err := os.Stat(sysctlConf); os.IsNotExist(err) {
		if err := os.WriteFile(sysctlConf, []byte("net.ipv4.ip_forward=1\n"), 0o644); err != nil {
			log.Printf("exit-node redirect: persist ip_forward: %v", err)
		}
	}

	portStr := strconv.Itoa(listenPort)
	// Always intercept HTTPS and Postgres; add any other ports declared by
	// ConnRouter endpoints (clickhouse_native 9000/9440, etc.).
	seen := map[string]bool{"443": true, "5432": true}
	ports := []string{"443", "5432"}
	for _, p := range extraPorts {
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	for _, dport := range ports {
		// TCP: REDIRECT to our listen port so SO_ORIGINAL_DST can recover the dst.
		tcpArgs := []string{"-t", "nat", "-i", "tailscale0", "-p", "tcp", "--dport", dport, "-j", "REDIRECT", "--to-port", portStr}
		if exec.Command("iptables", append([]string{"-C", "PREROUTING"}, tcpArgs...)...).Run() != nil {
			insert := exec.Command("iptables", append([]string{"-I", "PREROUTING", "1"}, tcpArgs...)...)
			if out, err := insert.CombinedOutput(); err != nil {
				log.Printf("exit-node redirect: iptables tcp dport %s: %v: %s", dport, err, out)
			} else {
				log.Printf("exit-node redirect: installed iptables REDIRECT tcp/%s → %s", dport, portStr)
			}
		}
		// UDP: REJECT so QUIC/HTTP3 fails fast and clients fall back to TCP.
		// Without this, UDP 443 bypasses MITM — on par with WireGuard mode which
		// captures all traffic on the tun interface.
		udpArgs := []string{"-i", "tailscale0", "-p", "udp", "--dport", dport, "-j", "REJECT", "--reject-with", "icmp-port-unreachable"}
		if exec.Command("iptables", append([]string{"-C", "FORWARD"}, udpArgs...)...).Run() != nil {
			insert := exec.Command("iptables", append([]string{"-I", "FORWARD", "1"}, udpArgs...)...)
			if out, err := insert.CombinedOutput(); err != nil {
				log.Printf("exit-node redirect: iptables udp dport %s: %v: %s", dport, err, out)
			} else {
				log.Printf("exit-node redirect: installed iptables REJECT udp/%s (force TCP fallback)", dport)
			}
		}
	}
}

func unwrapTCPConn(c net.Conn) *net.TCPConn {
	if tc, ok := c.(*net.TCPConn); ok {
		return tc
	}
	if bc, ok := c.(*bufferedConn); ok {
		if tc, ok := bc.Conn.(*net.TCPConn); ok {
			return tc
		}
	}
	return nil
}
