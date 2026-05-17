//go:build linux

package main

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/denoland/clawpatrol/dnsvip"
)

const (
	soOriginalDst     = 80 // SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST (linux/in.h, linux/netfilter_ipv6/ip6_tables.h)
	ipRecvOrigDstAddr = 20 // IP_RECVORIGDSTADDR (linux/in.h) — ancillary per-datagram original dst
)

// originalDst returns the pre-NAT destination of c when the connection was
// redirected by an iptables REDIRECT rule. Tries IPv4 first then IPv6.
// Returns ok=false for non-TCP conns or when no NAT entry exists.
func originalDst(c net.Conn) (ip string, port uint16, ok bool) {
	tc := unwrapTCPConn(c)
	if tc == nil {
		return "", 0, false
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return "", 0, false
	}

	// IPv4
	var sa4 syscall.RawSockaddrInet4
	saLen4 := uint32(syscall.SizeofSockaddrInet4)
	var soErr error
	_ = raw.Control(func(fd uintptr) {
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
			fd, syscall.IPPROTO_IP, soOriginalDst,
			uintptr(unsafe.Pointer(&sa4)),
			uintptr(unsafe.Pointer(&saLen4)),
			0)
		if errno != 0 {
			soErr = errno
		}
	})
	if soErr == nil {
		dstIP := net.IP(sa4.Addr[:]).String()
		dstPort := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa4.Port))[:])
		return dstIP, dstPort, true
	}

	// IPv6 (IP6T_SO_ORIGINAL_DST, same constant value on IPPROTO_IPV6)
	var sa6 syscall.RawSockaddrInet6
	saLen6 := uint32(syscall.SizeofSockaddrInet6)
	soErr = nil
	_ = raw.Control(func(fd uintptr) {
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
			fd, syscall.IPPROTO_IPV6, soOriginalDst,
			uintptr(unsafe.Pointer(&sa6)),
			uintptr(unsafe.Pointer(&saLen6)),
			0)
		if errno != 0 {
			soErr = errno
		}
	})
	if soErr == nil {
		dstIP := net.IP(sa6.Addr[:]).String()
		dstPort := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa6.Port))[:])
		return dstIP, dstPort, true
	}
	return "", 0, false
}

// startUDPDNSListener binds a UDP socket on port and serves DNS queries.
// iptables PREROUTING REDIRECT sends port-53 UDP from tailscale0 here;
// IP_RECVORIGDSTADDR recovers the DNS server the client was reaching so
// dnsvip can forward non-VIP names to the right upstream.
func startUDPDNSListener(port int, dvip *dnsvip.Allocator) {
	if port == 0 || dvip == nil {
		return
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		log.Printf("udp dns listener: %v", err)
		return
	}
	if rc, err := conn.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) {
			if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipRecvOrigDstAddr, 1); err != nil {
				log.Printf("udp dns: IP_RECVORIGDSTADDR: %v", err)
			}
		})
	}
	log.Printf("udp dns listener ready on :%d", port)
	go func() {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4096)
		oob := make([]byte, 256)
		for {
			n, oobn, _, addr, err := conn.ReadMsgUDP(buf, oob)
			if err != nil {
				if !isNetClosedError(err) {
					log.Printf("udp dns: recv: %v", err)
				}
				return
			}
			origDstIP := parseUDPOrigDstIP(oob[:oobn])
			resp := dvip.HandlePacket(buf[:n], origDstIP)
			if resp == nil {
				continue
			}
			_, _ = conn.WriteToUDP(resp, addr)
		}
	}()
}

// parseUDPOrigDstIP extracts the original destination IP from recvmsg
// ancillary data (IP_ORIGDSTADDR cmsg). Returns "" if not present.
func parseUDPOrigDstIP(oob []byte) string {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return ""
	}
	for _, m := range msgs {
		if m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == ipRecvOrigDstAddr {
			if len(m.Data) >= syscall.SizeofSockaddrInet4 {
				var sa syscall.RawSockaddrInet4
				copy((*[syscall.SizeofSockaddrInet4]byte)(unsafe.Pointer(&sa))[:], m.Data)
				return net.IP(sa.Addr[:]).String()
			}
		}
	}
	return ""
}

// installExitNodeRedirect installs packet-filter rules so exit-node TCP traffic
// arriving on tailscale0 is REDIRECT-ed to the gateway's listen port (recovered
// via SO_ORIGINAL_DST), UDP/53 is likewise REDIRECT-ed (served by the UDP DNS
// listener started separately), and UDP on all other intercepted ports is
// REJECT-ed to force QUIC→TCP fallback.
//
// Tries iptables/ip6tables first; falls back to nft (nftables) on systems where
// iptables is not installed. nftables uses an inet table which covers both
// address families in one ruleset.
//
// Idempotent: iptables rules are checked with -C before insertion; the nft path
// flushes and rebuilds the clawpatrol table on every call.
func installExitNodeRedirect(listenPort int, extraPorts []string) {
	if listenPort == 0 {
		return
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		log.Printf("exit-node redirect: ip_forward: %v", err)
	}
	const sysctlConf = "/etc/sysctl.d/99-clawpatrol-forward.conf"
	if _, err := os.Stat(sysctlConf); os.IsNotExist(err) {
		_ = os.WriteFile(sysctlConf, []byte("net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n"), 0o644)
	}

	portStr := strconv.Itoa(listenPort)

	// Port 53 is TCP-only REDIRECT + UDP REDIRECT (served by DNS listener).
	// Other ports get TCP REDIRECT + UDP REJECT (force QUIC→TCP fallback).
	seen := map[string]bool{"53": true, "443": true, "5432": true}
	tcpPorts := []string{"53", "443", "5432"} // TCP REDIRECT
	udpDNSPorts := []string{"53"}             // UDP REDIRECT → dns listener
	udpRejectPorts := []string{"443", "5432"} // UDP REJECT → QUIC fallback
	for _, p := range extraPorts {
		if !seen[p] {
			seen[p] = true
			tcpPorts = append(tcpPorts, p)
			udpRejectPorts = append(udpRejectPorts, p)
		}
	}

	_, iptablesErr := exec.LookPath("iptables")
	if iptablesErr == nil {
		installIPTables(portStr, tcpPorts, udpDNSPorts, udpRejectPorts)
	} else {
		installNFTables(portStr, tcpPorts, udpDNSPorts, udpRejectPorts)
	}
}

// installIPTables installs rules via iptables + ip6tables.
func installIPTables(portStr string, tcpPorts, udpDNSPorts, udpRejectPorts []string) {
	for _, bin := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		for _, dport := range tcpPorts {
			args := []string{"-t", "nat", "-i", "tailscale0", "-p", "tcp", "--dport", dport, "-j", "REDIRECT", "--to-port", portStr}
			if exec.Command(bin, append([]string{"-C", "PREROUTING"}, args...)...).Run() != nil {
				if out, err := exec.Command(bin, append([]string{"-I", "PREROUTING", "1"}, args...)...).CombinedOutput(); err != nil {
					log.Printf("exit-node redirect: %s tcp/%s: %v: %s", bin, dport, err, out)
				} else {
					log.Printf("exit-node redirect: %s REDIRECT tcp/%s → %s", bin, dport, portStr)
				}
			}
		}
		for _, dport := range udpDNSPorts {
			args := []string{"-t", "nat", "-i", "tailscale0", "-p", "udp", "--dport", dport, "-j", "REDIRECT", "--to-port", portStr}
			if exec.Command(bin, append([]string{"-C", "PREROUTING"}, args...)...).Run() != nil {
				if out, err := exec.Command(bin, append([]string{"-I", "PREROUTING", "1"}, args...)...).CombinedOutput(); err != nil {
					log.Printf("exit-node redirect: %s udp/%s: %v: %s", bin, dport, err, out)
				} else {
					log.Printf("exit-node redirect: %s REDIRECT udp/%s → %s", bin, dport, portStr)
				}
			}
		}
		for _, dport := range udpRejectPorts {
			args := []string{"-i", "tailscale0", "-p", "udp", "--dport", dport, "-j", "REJECT", "--reject-with", "icmp-port-unreachable"}
			if exec.Command(bin, append([]string{"-C", "FORWARD"}, args...)...).Run() != nil {
				if out, err := exec.Command(bin, append([]string{"-I", "FORWARD", "1"}, args...)...).CombinedOutput(); err != nil {
					log.Printf("exit-node redirect: %s REJECT udp/%s: %v: %s", bin, dport, err, out)
				} else {
					log.Printf("exit-node redirect: %s REJECT udp/%s (QUIC fallback)", bin, dport)
				}
			}
		}
	}
}

// installNFTables installs rules via nft (nftables) using an inet table
// that covers both IPv4 and IPv6 in a single ruleset. Idempotent: the
// clawpatrol table is flushed and rebuilt on every call.
func installNFTables(portStr string, tcpPorts, udpDNSPorts, udpRejectPorts []string) {
	if _, err := exec.LookPath("nft"); err != nil {
		log.Printf("exit-node redirect: neither iptables nor nft found; install one of them")
		return
	}

	tcpSet := "{ " + strings.Join(tcpPorts, ", ") + " }"
	udpDNSSet := "{ " + strings.Join(udpDNSPorts, ", ") + " }"

	// Flush + rebuild our dedicated table for idempotency.
	exec.Command("nft", "delete", "table", "inet", "clawpatrol").Run() //nolint:errcheck

	script := strings.Join([]string{
		"table inet clawpatrol {",
		"  chain prerouting {",
		"    type nat hook prerouting priority -100;",
		`    iifname "tailscale0" tcp dport ` + tcpSet + " redirect to :" + portStr + ";",
		`    iifname "tailscale0" udp dport ` + udpDNSSet + " redirect to :" + portStr + ";",
		"  }",
	}, "\n")

	if len(udpRejectPorts) > 0 {
		udpRejectSet := "{ " + strings.Join(udpRejectPorts, ", ") + " }"
		script += "\n" + strings.Join([]string{
			"  chain forward {",
			"    type filter hook forward priority 0;",
			`    iifname "tailscale0" udp dport ` + udpRejectSet + " reject;",
			"  }",
		}, "\n")
	}
	script += "\n}"

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("exit-node redirect: nft: %v: %s", err, out)
	} else {
		log.Printf("exit-node redirect: nftables rules installed (inet clawpatrol, covers IPv4+IPv6)")
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

func isNetClosedError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "use of closed network connection")
}
