// Package dnsvip handles DNS interception and virtual-IP allocation
// for non-HTTP endpoints that can't be disambiguated at TCP-accept
// time. The canonical case is SSH: a TCP connection to port 22
// carries no SNI / Host header, so an agent dialling
// "ssh build.example.com" reaches the gateway's WG forwarder with
// nothing more than a destination IP. To know which logical endpoint
// the user meant, clawpatrol gives every SSH-able hostname a unique
// IP from a private range (10.78.0.0/16 v4, fd78::/64 v6) and answers
// agent DNS queries with those instead of the real upstream IP. When
// the connection comes back, the destination IP is the VIP — and the
// VIP is keyed to exactly one hostname.
//
// VIPs are stable across both restarts and policy reloads (persisted
// to <state_dir>/dnsvip.json). When a hostname leaves policy its slot
// is freed and reused by the next allocation, so the table doesn't
// grow without bound across long-lived gateways.
//
// The package depends on miekg/dns only for wire-format parsing and
// serialisation; the server loops are hand-rolled because the
// netstack hands us per-flow conns rather than a listener miekg/dns
// could `ActivateAndServe` against.
package dnsvip

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/denoland/clawpatrol/config"
)

// hostResolver routes A/AAAA lookups for non-VIP names through the
// gateway's host resolver chain — /etc/hosts + /etc/resolv.conf +
// any platform-native split-horizon entries (Tailscale MagicDNS,
// VPN-pushed servers, corp resolvers). PreferGo bypasses cgo's
// getaddrinfo so macOS mDNSResponder doesn't coalesce the gateway's
// own lookup onto the agent's in-flight tunnelled query and deadlock
// both — the same hardening unclaw landed in dns.ts.
var hostResolver = &net.Resolver{PreferGo: true}

// RequiresVIP is the marker an endpoint plugin's body implements when
// its hostnames need DNS-VIP interception (because the wire protocol
// can't be routed by destination IP alone). The dnsvip Allocator picks
// it up at policy build time and assigns a VIP per hostname.
//
// Endpoints that opt in must also implement runtime.ConnRouter — the
// dnsvip walker reads the host:port list from there to keep the
// "what hosts does this endpoint claim" knowledge in one place.
type RequiresVIP interface {
	RequiresVIP() bool
}

// EndpointHit is what LookupVIP returns: the endpoint(s) bound to a
// VIP plus the port the host:port binding declared. Multiple endpoints
// can share a hostname (and therefore a VIP) — caller filters by
// profile and matches DstPort to pick.
type EndpointHit struct {
	Endpoint *config.CompiledEndpoint
	Port     uint16
}

// Default CIDRs. Picked to be unlikely to collide with the WG subnet
// (10.55.0.0/24 in the example config) and outside any common LAN
// range. Operators with constraints override via the gateway block.
var (
	DefaultCIDR4 = netip.MustParsePrefix("10.78.0.0/16")
	DefaultCIDR6 = netip.MustParsePrefix("fd78::/64")
)

// MaxID caps allocations. v4 /16 holds 65535 usable IDs; v6 /64
// would technically hold 2^32 but we share a single ID space with v4
// so the v4 ceiling rules. Sentinel keeps allocator panics out of
// pathological reload loops.
const MaxID uint32 = 0xFFFE

type entry struct {
	ID       uint32     `json:"id"`
	Hostname string     `json:"hostname"`
	V4       netip.Addr `json:"v4"`
	V6       netip.Addr `json:"v6"`
}

type persistFile struct {
	Version int     `json:"version"`
	Entries []entry `json:"entries"`
}

// Allocator owns the hostname↔VIP table and serves DNS over the
// netstack-supplied conns. Construction loads from disk; the gateway
// calls RebuildFromPolicy on every policy load to reconcile
// allocations against the current endpoint set.
type Allocator struct {
	statePath string
	cidr4     netip.Prefix
	cidr6     netip.Prefix

	mu        sync.RWMutex
	byName    map[string]*entry        // hostname → entry
	byV4      map[netip.Addr]*entry    // 10.78.x.y → entry
	byV6      map[netip.Addr]*entry    // fd78::N → entry
	endpoints map[string][]EndpointHit // hostname → hits
	free      []uint32                 // recycled IDs
	used      map[uint32]struct{}      // ID set, for fast in-use check
}

// New constructs an allocator and loads any existing state from
// stateDir/dnsvip.json. cidr4/cidr6 may be passed as zero-valued
// netip.Prefix to use the package defaults. A non-existent state
// file is fine — the allocator starts empty.
func New(stateDir string, cidr4, cidr6 netip.Prefix) (*Allocator, error) {
	if !cidr4.IsValid() {
		cidr4 = DefaultCIDR4
	}
	if !cidr6.IsValid() {
		cidr6 = DefaultCIDR6
	}
	if !cidr4.Addr().Is4() {
		return nil, fmt.Errorf("cidr4 must be IPv4: %s", cidr4)
	}
	if !cidr6.Addr().Is6() || cidr6.Addr().Is4In6() {
		return nil, fmt.Errorf("cidr6 must be IPv6: %s", cidr6)
	}
	a := &Allocator{
		statePath: filepath.Join(stateDir, "dnsvip.json"),
		cidr4:     cidr4,
		cidr6:     cidr6,
		byName:    map[string]*entry{},
		byV4:      map[netip.Addr]*entry{},
		byV6:      map[netip.Addr]*entry{},
		endpoints: map[string][]EndpointHit{},
		used:      map[uint32]struct{}{},
	}
	if err := a.load(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Allocator) load() error {
	data, err := os.ReadFile(a.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("dnsvip: read %s: %w", a.statePath, err)
	}
	var f persistFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("dnsvip: parse %s: %w", a.statePath, err)
	}
	for i := range f.Entries {
		e := &f.Entries[i]
		// Defensive: skip entries whose VIPs fall outside the
		// configured CIDRs (operator changed the prefix between
		// boots). They'll be reallocated fresh on next rebuild.
		if !a.cidr4.Contains(e.V4) || !a.cidr6.Contains(e.V6) {
			log.Printf("dnsvip: dropping persisted entry %s — VIP outside configured CIDRs", e.Hostname)
			continue
		}
		a.byName[e.Hostname] = e
		a.byV4[e.V4] = e
		a.byV6[e.V6] = e
		a.used[e.ID] = struct{}{}
	}
	return nil
}

func (a *Allocator) persistLocked() error {
	if a.statePath == "" {
		return nil
	}
	out := persistFile{Version: 1}
	for _, e := range a.byName {
		out.Entries = append(out.Entries, *e)
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].ID < out.Entries[j].ID })
	buf, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(a.statePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "dnsvip-*.json.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(buf); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, a.statePath)
}

// vipForID derives the (v4, v6) pair for an ID. v4 occupies the last
// two octets of cidr4; v6 occupies the last 32 bits of cidr6. ID 0 is
// reserved (network address); IDs start at 1.
func (a *Allocator) vipForID(id uint32) (netip.Addr, netip.Addr) {
	v4 := a.cidr4.Addr().As4()
	v4[2] = byte(id >> 8)
	v4[3] = byte(id)
	v6 := a.cidr6.Addr().As16()
	v6[12] = byte(id >> 24)
	v6[13] = byte(id >> 16)
	v6[14] = byte(id >> 8)
	v6[15] = byte(id)
	return netip.AddrFrom4(v4), netip.AddrFrom16(v6)
}

// allocateLocked picks an unused ID — preferring the free-list before
// scanning forward — and creates an entry for hostname.
func (a *Allocator) allocateLocked(hostname string) (*entry, error) {
	// Free-list first: deterministic recycling means deleted slots
	// fill in before we extend the table.
	for len(a.free) > 0 {
		id := a.free[0]
		a.free = a.free[1:]
		if _, taken := a.used[id]; taken {
			continue
		}
		return a.makeEntry(id, hostname), nil
	}
	for id := uint32(1); id <= MaxID; id++ {
		if _, taken := a.used[id]; taken {
			continue
		}
		return a.makeEntry(id, hostname), nil
	}
	return nil, fmt.Errorf("dnsvip: VIP pool exhausted (%d allocated)", len(a.used))
}

func (a *Allocator) makeEntry(id uint32, hostname string) *entry {
	v4, v6 := a.vipForID(id)
	e := &entry{ID: id, Hostname: hostname, V4: v4, V6: v6}
	a.byName[hostname] = e
	a.byV4[v4] = e
	a.byV6[v6] = e
	a.used[id] = struct{}{}
	return e
}

// RebuildFromPolicy reconciles the VIP table against the current
// compiled policy. Hostnames newly in policy get fresh VIP pairs;
// hostnames that disappeared have their pair freed back to the
// free-list. The endpoint→hit map is rebuilt from scratch every
// time. Persists on success.
func (a *Allocator) RebuildFromPolicy(policy *config.CompiledPolicy) error {
	if a == nil {
		return nil
	}
	required := collectRequiredHosts(policy)

	a.mu.Lock()
	defer a.mu.Unlock()

	// Free entries no longer required.
	for hostname, e := range a.byName {
		if _, keep := required[hostname]; keep {
			continue
		}
		delete(a.byName, hostname)
		delete(a.byV4, e.V4)
		delete(a.byV6, e.V6)
		delete(a.used, e.ID)
		a.free = append(a.free, e.ID)
	}
	// Allocate new ones in deterministic hostname order so persisted
	// IDs match across machines that load the same policy from
	// scratch (cosmetic — VIP order shouldn't be operator-visible
	// except when comparing dnsvip.json across replicas).
	var newHosts []string
	for h := range required {
		if _, exists := a.byName[h]; !exists {
			newHosts = append(newHosts, h)
		}
	}
	sort.Strings(newHosts)
	for _, h := range newHosts {
		if _, err := a.allocateLocked(h); err != nil {
			return err
		}
	}

	// Rebuild the endpoint→hits map.
	a.endpoints = map[string][]EndpointHit{}
	for hostname, hits := range required {
		a.endpoints[hostname] = hits
	}

	return a.persistLocked()
}

// collectRequiredHosts walks the policy and returns the hostname →
// []EndpointHit map for endpoints that opted into VIPs. Endpoints
// must also be ConnRouters — that's where we get the host:port list
// (the same one ConnIndex uses for direct-IP routing). A host string
// without a port falls back to that protocol's default; SSH is the
// only RequiresVIP plugin in v1 so the default is 22.
//
// IP-literal entries are skipped: VIPs exist to recover hostname
// identity from a TCP dst IP, but agents dialing an IP literal never
// issue a DNS query, so allocating a VIP for one is wasted state. The
// gateway's direct-IP dispatch path (consulting ConnIndex inside the
// WG forwarder's default case) covers those entries instead.
func collectRequiredHosts(policy *config.CompiledPolicy) map[string][]EndpointHit {
	out := map[string][]EndpointHit{}
	if policy == nil {
		return out
	}
	for _, ep := range policy.Endpoints {
		req, ok := ep.Body.(RequiresVIP)
		if !ok || !req.RequiresVIP() {
			continue
		}
		// Use the compiled Hosts list (already populated via
		// EndpointHosts()) — same source ConnIndex consumes.
		for _, hp := range ep.Hosts {
			host, portStr, err := net.SplitHostPort(hp)
			if err != nil {
				host = hp
				portStr = ""
			}
			if host == "" {
				continue
			}
			if net.ParseIP(host) != nil {
				continue
			}
			var port uint16 = defaultPortFor(ep)
			if portStr != "" {
				var p uint16
				if _, err := fmt.Sscanf(portStr, "%d", &p); err == nil {
					port = p
				}
			}
			out[host] = append(out[host], EndpointHit{Endpoint: ep, Port: port})
		}
	}
	return out
}

// defaultPortFor returns the default port for a VIP-needing endpoint
// when its host string omits one. SSH is the only RequiresVIP plugin
// today; future plugins can extend the switch.
func defaultPortFor(ep *config.CompiledEndpoint) uint16 {
	switch ep.Plugin.Type {
	case "ssh":
		return 22
	}
	return 0
}

// IsVIP reports whether dstIP falls in either configured VIP range.
// dstIP is the netstack-extracted destination string (already in
// canonical form — IPv4 dotted, IPv6 colon-separated).
func (a *Allocator) IsVIP(dstIP string) bool {
	if a == nil {
		return false
	}
	addr, err := netip.ParseAddr(dstIP)
	if err != nil {
		return false
	}
	return a.cidr4.Contains(addr) || a.cidr6.Contains(addr)
}

// LookupVIP resolves a destination IP back to the EndpointHits bound
// to the corresponding hostname. Empty result means the IP isn't a
// recognised VIP (caller falls back to ConnIndex).
func (a *Allocator) LookupVIP(dstIP string) (hostname string, hits []EndpointHit) {
	if a == nil {
		return "", nil
	}
	addr, err := netip.ParseAddr(dstIP)
	if err != nil {
		return "", nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	var e *entry
	if addr.Is4() {
		e = a.byV4[addr]
	} else {
		e = a.byV6[addr]
	}
	if e == nil {
		return "", nil
	}
	return e.Hostname, a.endpoints[e.Hostname]
}

// HostnameFor returns the hostname behind a VIP, or "" if not a VIP.
// Convenience for tests / logging.
func (a *Allocator) HostnameFor(addr netip.Addr) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var e *entry
	if addr.Is4() {
		e = a.byV4[addr]
	} else {
		e = a.byV6[addr]
	}
	if e == nil {
		return ""
	}
	return e.Hostname
}

// VIPsFor returns the (v4, v6) pair for a hostname, both zero when
// not allocated. Used by tests / dashboard surfaces.
func (a *Allocator) VIPsFor(hostname string) (netip.Addr, netip.Addr) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	e := a.byName[hostname]
	if e == nil {
		return netip.Addr{}, netip.Addr{}
	}
	return e.V4, e.V6
}

// ── DNS handling ──────────────────────────────────────────────────────

// ServeUDP loops over a single UDP "conn" handed up by the netstack.
// Each agent's UDP flow gets its own gonet UDP conn, so we read one
// datagram, build a response, write it back, and continue until the
// peer goes idle. Mirrors the relayUDP loop pattern in wireguard.go.
//
// dstIP is the address the agent thought it was talking to (the
// system-resolver IP it picked, e.g. 1.1.1.1). When a query falls
// outside the VIP table we forward it there verbatim so the agent's
// existing DNS configuration keeps working — the gateway hijacks
// only the names it has policy for.
func (a *Allocator) ServeUDP(c net.Conn, dstIP string) {
	defer c.Close()
	buf := make([]byte, 4096)
	for {
		_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		resp := a.handleWire(buf[:n], dstIP)
		if resp == nil {
			continue
		}
		_, _ = c.Write(resp)
	}
}

// ServeTCP serves the RFC 1035 length-prefixed framing variant. The
// netstack gives us one TCP conn per agent flow; we loop until the
// agent closes (DNS-over-TCP supports pipelining).
func (a *Allocator) ServeTCP(c net.Conn, dstIP string) {
	defer c.Close()
	hdr := make([]byte, 2)
	for {
		_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		length := binary.BigEndian.Uint16(hdr)
		if length == 0 {
			continue
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		resp := a.handleWire(body, dstIP)
		if resp == nil {
			continue
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

// handleWire parses the wire bytes and returns the response wire
// bytes — the on-the-wire return value, ready to ship. A nil return
// means we couldn't even build a SERVFAIL (parse failure of the
// agent's bytes is the only path) and the caller should drop.
func (a *Allocator) handleWire(in []byte, dstIP string) []byte {
	q := new(dns.Msg)
	if err := q.Unpack(in); err != nil {
		log.Printf("dnsvip: parse query: %v", err)
		return nil
	}
	resp := a.handleQuery(q, dstIP)
	if resp == nil {
		return nil
	}
	out, err := resp.Pack()
	if err != nil {
		log.Printf("dnsvip: pack response: %v", err)
		return nil
	}
	return out
}

// handleQuery is the actual responder. Splits intercepted from
// non-intercepted: if any question targets a known VIP-hostname we
// answer locally; otherwise we forward the entire message to dstIP
// verbatim. A query for a known hostname's "wrong" type (e.g. MX) is
// answered NOERROR + empty so resolvers don't loop into upstream and
// learn the real address.
func (a *Allocator) handleQuery(q *dns.Msg, dstIP string) *dns.Msg {
	if len(q.Question) == 0 {
		return errorResp(q, dns.RcodeFormatError)
	}
	intercept := false
	for _, qq := range q.Question {
		if a.intercepts(strings.TrimSuffix(qq.Name, ".")) {
			intercept = true
			break
		}
	}
	if !intercept {
		return a.forwardUpstream(q, dstIP)
	}
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.Authoritative = true
	resp.RecursionAvailable = true
	for _, qq := range q.Question {
		host := strings.TrimSuffix(qq.Name, ".")
		v4, v6 := a.VIPsFor(host)
		switch qq.Qtype {
		case dns.TypeA:
			if v4.IsValid() {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: qq.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
					A:   v4.AsSlice(),
				})
			}
		case dns.TypeAAAA:
			if v6.IsValid() {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: qq.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30},
					AAAA: v6.AsSlice(),
				})
			}
		default:
			// Other types (MX, TXT, SRV, NS) on intercepted names
			// → NOERROR + empty answer. We don't proxy them upstream
			// because doing so leaks the real IP and also opens an
			// inconsistency window where a client might race the
			// upstream answer ahead of the intercepted A.
		}
	}
	return resp
}

func (a *Allocator) intercepts(hostname string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.byName[hostname]
	return ok
}

// forwardUpstream answers a query the VIP table didn't claim. For A
// and AAAA we synthesise the response from the gateway's host
// resolver — /etc/hosts, /etc/resolv.conf, and any platform-native
// split-horizon backends — so internal names the operator's machine
// can resolve work transparently inside `clawpatrol run`. The naive
// alternative (forwarding verbatim to the dstIP the agent's
// resolv.conf pointed at — typically 1.1.1.1 from the WG conf's
// PostUp) produces NXDOMAIN for any internal name and is the bug
// this layer exists to fix.
//
// Other record types (TXT / SRV / MX / CAA / etc.) keep their raw-
// relay behavior. Go's stdlib doesn't expose a generic "any record
// type" lookup, so synthesising from the local resolver would mean
// re-implementing per-type serialisation against an incomplete API
// surface. Relaying preserves wire fidelity (EDNS, flags, DNSSEC
// records) and matches operator intent — if the agent's resolv.conf
// names a specific resolver, that resolver answers TXT lookups.
//
// Errors collapse to NXDOMAIN (synthesised path) or SERVFAIL (relay
// path). The split keeps the synth path's "name doesn't exist"
// signal distinct from the relay path's "upstream unreachable".
func (a *Allocator) forwardUpstream(q *dns.Msg, dstIP string) *dns.Msg {
	if len(q.Question) == 0 {
		return errorResp(q, dns.RcodeFormatError)
	}
	qd := q.Question[0]
	switch qd.Qtype {
	case dns.TypeA:
		return synthIPResponse(q, "ip4")
	case dns.TypeAAAA:
		return synthIPResponse(q, "ip6")
	default:
		return relayUpstream(q, dstIP)
	}
}

// synthIPResponse resolves the query name via the gateway's host
// resolver and builds an A or AAAA response. network is "ip4" or
// "ip6"; the returned message reuses the query's id and question.
func synthIPResponse(q *dns.Msg, network string) *dns.Msg {
	qd := q.Question[0]
	name := strings.TrimSuffix(qd.Name, ".")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := hostResolver.LookupIP(ctx, network, name)
	if err != nil || len(ips) == 0 {
		// LookupIP folds DNS error codes (NXDOMAIN, SERVFAIL,
		// timeout) into a single error type. Treat any failure as
		// NXDOMAIN — the gateway has already exhausted its local
		// resolver chain, and there's nowhere else to consult that
		// would know about an internal name the operator's machine
		// doesn't know about either.
		return errorResp(q, dns.RcodeNameError)
	}
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.RecursionAvailable = true
	for _, ip := range ips {
		hdr := dns.RR_Header{
			Name:   qd.Name,
			Rrtype: qd.Qtype,
			Class:  dns.ClassINET,
			Ttl:    30,
		}
		switch qd.Qtype {
		case dns.TypeA:
			if ip4 := ip.To4(); ip4 != nil {
				resp.Answer = append(resp.Answer, &dns.A{Hdr: hdr, A: ip4})
			}
		case dns.TypeAAAA:
			if ip4 := ip.To4(); ip4 == nil {
				resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip})
			}
		}
	}
	if len(resp.Answer) == 0 {
		// Resolver returned addresses but none matched the query
		// family (e.g. AAAA query, IPv4-only host). Empty NOERROR
		// response — same shape DNS servers use for "name exists,
		// no records of this type."
		return resp
	}
	return resp
}

// relayUpstream forwards the query verbatim to the dstIP the agent
// originally addressed and returns whatever comes back. Used for
// record types the synth path doesn't handle.
func relayUpstream(q *dns.Msg, dstIP string) *dns.Msg {
	if dstIP == "" {
		return errorResp(q, dns.RcodeServerFailure)
	}
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	in, _, err := c.Exchange(q, net.JoinHostPort(dstIP, "53"))
	if err != nil {
		log.Printf("dnsvip: relay to %s: %v", dstIP, err)
		return errorResp(q, dns.RcodeServerFailure)
	}
	return in
}

func errorResp(q *dns.Msg, rcode int) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(q, rcode)
	return r
}
