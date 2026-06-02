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
// to the dnsvip_allocations sqlite table). When a hostname leaves
// policy its slot is freed and reused by the next allocation, so the
// table doesn't grow without bound across long-lived gateways.
//
// The package depends on miekg/dns only for wire-format parsing and
// serialisation; the server loops are hand-rolled because the
// netstack hands us per-flow conns rather than a listener miekg/dns
// could `ActivateAndServe` against.
package dnsvip

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/hostmatch"
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
	ID       uint32
	Hostname string
	V4       netip.Addr
	V6       netip.Addr
}

// Allocator owns the hostname↔VIP table and serves DNS over the
// netstack-supplied conns. Construction loads from sqlite; the gateway
// calls RebuildFromPolicy on every policy load to reconcile
// allocations against the current endpoint set.
type Allocator struct {
	db    *sql.DB
	cidr4 netip.Prefix
	cidr6 netip.Prefix

	mu        sync.RWMutex
	byName    map[string]*entry        // hostname → entry
	byV4      map[netip.Addr]*entry    // 10.78.x.y → entry
	byV6      map[netip.Addr]*entry    // fd78::N → entry
	endpoints map[string][]EndpointHit // hostname → hits
	patterns  []patternBinding         // wildcard host bindings, longest suffix first
	free      []uint32                 // recycled IDs
	used      map[uint32]struct{}      // ID set, for fast in-use check
}

// patternBinding holds one wildcard host declaration plus the
// EndpointHits that should fire when a DNS query (or post-allocation
// VIP lookup) lands on a name matching Pattern. Patterns are kept in
// declaration order at the slice level; RebuildFromPolicy sorts them
// by descending length so the lazy-lookup walk returns the most
// specific match first.
type patternBinding struct {
	Pattern string
	Port    uint16
	Hits    []EndpointHit
}

// New constructs an allocator and loads any existing state from the
// dnsvip_allocations table. cidr4/cidr6 may be passed as zero-valued
// netip.Prefix to use the package defaults. An empty table is fine —
// the allocator starts empty.
func New(db *sql.DB, cidr4, cidr6 netip.Prefix) (*Allocator, error) {
	if db == nil {
		return nil, fmt.Errorf("dnsvip: nil db")
	}
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
		db:        db,
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
	rows, err := a.db.Query(`SELECT id, hostname, v4, v6 FROM dnsvip_allocations`)
	if err != nil {
		return fmt.Errorf("dnsvip: read: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			id           int64
			host, v4, v6 string
		)
		if err := rows.Scan(&id, &host, &v4, &v6); err != nil {
			return fmt.Errorf("dnsvip: scan: %w", err)
		}
		v4a, err := netip.ParseAddr(v4)
		if err != nil {
			log.Printf("dnsvip: dropping persisted entry %s — bad v4 %q: %v", host, v4, err)
			continue
		}
		v6a, err := netip.ParseAddr(v6)
		if err != nil {
			log.Printf("dnsvip: dropping persisted entry %s — bad v6 %q: %v", host, v6, err)
			continue
		}
		// Defensive: skip entries whose VIPs fall outside the
		// configured CIDRs (operator changed the prefix between
		// boots). They'll be reallocated fresh on next rebuild.
		if !a.cidr4.Contains(v4a) || !a.cidr6.Contains(v6a) {
			log.Printf("dnsvip: dropping persisted entry %s — VIP outside configured CIDRs", host)
			continue
		}
		e := &entry{ID: uint32(id), Hostname: host, V4: v4a, V6: v6a}
		a.byName[host] = e
		a.byV4[v4a] = e
		a.byV6[v6a] = e
		a.used[e.ID] = struct{}{}
	}
	return rows.Err()
}

// persistLocked rewrites the dnsvip_allocations table to match the
// in-memory byName state. Wrapped in a tx so a crash mid-rebuild
// leaves the previous table intact — same atomicity the old
// rename-an-atomic-file path had.
func (a *Allocator) persistLocked() error {
	if a.db == nil {
		return nil
	}
	tx, err := a.db.Begin()
	if err != nil {
		return fmt.Errorf("dnsvip: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM dnsvip_allocations`); err != nil {
		return fmt.Errorf("dnsvip: delete allocations: %w", err)
	}
	// Sort for determinism; aids replica diffing + log scanning.
	entries := make([]*entry, 0, len(a.byName))
	for _, e := range a.byName {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	for _, e := range entries {
		if _, err := tx.Exec(
			`INSERT INTO dnsvip_allocations (id, hostname, v4, v6) VALUES (?, ?, ?, ?)`,
			e.ID, e.Hostname, e.V4.String(), e.V6.String(),
		); err != nil {
			return fmt.Errorf("dnsvip: insert id=%d host=%q: %w", e.ID, e.Hostname, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("dnsvip: commit: %w", err)
	}
	return nil
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
//
// Wildcard hosts (`hosts = ["*.foo.com"]`) don't pre-allocate VIPs;
// they install a pattern binding instead, and a lazy allocation
// happens the first time intercepts() sees a DNS query that matches.
// Lazy-allocated entries from previous policies survive a rebuild
// when their hostname still matches some current pattern — that's
// what keeps an agent's cached `s3.amazonaws.com → 10.78.0.5`
// mapping valid across reloads.
func (a *Allocator) RebuildFromPolicy(policy *config.CompiledPolicy) error {
	if a == nil {
		return nil
	}
	required, patterns := collectRequiredHosts(policy)

	a.mu.Lock()
	defer a.mu.Unlock()

	// Free entries that neither appear in the exact required set
	// nor match any current wildcard pattern. Lazy entries from a
	// previous policy whose pattern is gone are released back to
	// the free-list here; surviving lazy entries keep their VIPs.
	for hostname, e := range a.byName {
		if _, keep := required[hostname]; keep {
			continue
		}
		if matchPatternBindings(patterns, hostname) != nil {
			continue
		}
		delete(a.byName, hostname)
		delete(a.byV4, e.V4)
		delete(a.byV6, e.V6)
		delete(a.used, e.ID)
		a.free = append(a.free, e.ID)
	}
	// Allocate new exact entries in deterministic hostname order
	// so persisted IDs match across machines that load the same
	// policy from scratch (cosmetic — VIP order shouldn't be
	// operator-visible except when comparing dnsvip.json across
	// replicas).
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

	// Rebuild the endpoint→hits map. For each VIP currently held
	// (including surviving lazy entries) re-derive the hit list
	// from whichever side of the policy claims the hostname now.
	a.patterns = patterns
	a.endpoints = map[string][]EndpointHit{}
	for hostname, hits := range required {
		a.endpoints[hostname] = hits
	}
	for hostname := range a.byName {
		if _, ok := a.endpoints[hostname]; ok {
			continue
		}
		if p := matchPatternBindings(patterns, hostname); p != nil {
			a.endpoints[hostname] = p.Hits
		}
	}

	return a.persistLocked()
}

// matchPatternBindings returns the most specific (longest pattern)
// binding whose pattern matches hostname, or nil when none does.
// Caller must hold whichever lock is appropriate (the patterns slice
// is owned by Allocator.mu). patterns must already be sorted by
// descending pattern length.
func matchPatternBindings(patterns []patternBinding, hostname string) *patternBinding {
	hostname = strings.ToLower(hostname)
	for i := range patterns {
		p := &patterns[i]
		if hostmatch.MatchWildcard(p.Pattern, hostname) {
			return p
		}
	}
	return nil
}

// collectRequiredHosts walks the policy and returns two complementary
// views of the VIP-needing host set:
//
//   - exact map: hostname → []EndpointHit, pre-allocated at rebuild
//     time. Same shape and semantics the allocator has always had.
//   - patterns: wildcard `*.suffix` bindings the allocator walks
//     on-demand at DNS query time. No VIP exists yet for a pattern
//     entry; the allocator lazy-allocates on first hit.
//
// Endpoints must opt into VIPs (RequiresVIP marker on the body OR
// declare a tunnel — see CompiledEndpoint.RequiresVIP) and the
// hostnames must come off the compiled Hosts list (the same source
// ConnIndex consumes). A host string without a port falls back to
// that protocol's default; SSH is the only RequiresVIP plugin in v1
// so the default is 22.
//
// IP-literal entries are skipped: VIPs exist to recover hostname
// identity from a TCP dst IP, but agents dialing an IP literal never
// issue a DNS query, so allocating a VIP for one is wasted state. The
// gateway's direct-IP dispatch path covers those entries instead.
func collectRequiredHosts(policy *config.CompiledPolicy) (map[string][]EndpointHit, []patternBinding) {
	exact := map[string][]EndpointHit{}
	if policy == nil {
		return exact, nil
	}
	patternIdx := map[string]int{}
	var patterns []patternBinding
	for _, ep := range policy.Endpoints {
		if !ep.RequiresVIP() {
			continue
		}
		for _, hp := range ep.Hosts {
			host, portStr, err := hostmatch.SplitHostPort(hp)
			if err != nil || host == "" {
				continue
			}
			port := defaultPortFor(ep)
			if portStr != "" {
				var p uint16
				if _, err := fmt.Sscanf(portStr, "%d", &p); err == nil {
					port = p
				}
			}
			if hostmatch.IsWildcardHost(host) {
				key := strings.ToLower(host)
				idx, ok := patternIdx[key]
				if !ok {
					patternIdx[key] = len(patterns)
					patterns = append(patterns, patternBinding{Pattern: key, Port: port})
					idx = patternIdx[key]
				}
				patterns[idx].Hits = append(patterns[idx].Hits, EndpointHit{Endpoint: ep, Port: port})
				continue
			}
			if net.ParseIP(host) != nil {
				continue
			}
			exact[host] = append(exact[host], EndpointHit{Endpoint: ep, Port: port})
		}
	}
	sort.SliceStable(patterns, func(i, j int) bool {
		if len(patterns[i].Pattern) != len(patterns[j].Pattern) {
			return len(patterns[i].Pattern) > len(patterns[j].Pattern)
		}
		return patterns[i].Pattern < patterns[j].Pattern
	})
	return exact, patterns
}

// defaultPortFor returns the default port for a VIP-needing endpoint
// when its host string omits one.
func defaultPortFor(ep *config.CompiledEndpoint) uint16 {
	switch ep.Plugin.Type {
	case "ssh":
		return 22
	case "postgres":
		return 5432
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
	defer func() { _ = c.Close() }()
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
	defer func() { _ = c.Close() }()
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

// HandlePacket processes a single raw DNS wire-format datagram and returns
// the response datagram ready to send, or nil on parse error. Used by the
// exit-node UDP DNS listener; callers write the returned bytes directly.
func (a *Allocator) HandlePacket(in []byte, origDstIP string) []byte {
	return a.handleWire(in, origDstIP)
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

// intercepts reports whether hostname is bound to a VIP in this
// allocator. Falls through to the wildcard pattern table on exact
// miss and lazy-allocates a fresh VIP when a pattern claims the name
// — the first DNS query for a `*.amazonaws.com` host pins it to a
// stable VIP that persists across restarts (until the pattern leaves
// policy).
func (a *Allocator) intercepts(hostname string) bool {
	hostname = strings.ToLower(hostname)
	a.mu.RLock()
	if _, ok := a.byName[hostname]; ok {
		a.mu.RUnlock()
		return true
	}
	binding := matchPatternBindings(a.patterns, hostname)
	a.mu.RUnlock()
	if binding == nil {
		return false
	}
	return a.lazyAllocateForPattern(hostname)
}

// lazyAllocateForPattern reserves a VIP for hostname under the write
// lock. Returns true on success, false on pool exhaustion or DB
// failure (the gateway logs the failure and the agent's DNS query
// falls through to the upstream resolver — better than handing back a
// half-built entry).
func (a *Allocator) lazyAllocateForPattern(hostname string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Re-check under the write lock: a concurrent query might have
	// already allocated this name.
	if _, ok := a.byName[hostname]; ok {
		return true
	}
	binding := matchPatternBindings(a.patterns, hostname)
	if binding == nil {
		return false
	}
	if _, err := a.allocateLocked(hostname); err != nil {
		log.Printf("dnsvip: lazy-allocate %q: %v", hostname, err)
		return false
	}
	a.endpoints[hostname] = binding.Hits
	if err := a.persistLocked(); err != nil {
		log.Printf("dnsvip: persist lazy %q: %v", hostname, err)
		// State is still consistent in memory; persistence will
		// retry on the next allocation.
	}
	return true
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
