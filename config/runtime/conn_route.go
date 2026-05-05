package runtime

// Conn-routing for non-HTTP endpoints. Endpoint plugins whose body
// satisfies ConnRouter declare which dst tuples (host:port) they
// claim; the gateway resolves each via DNS once at policy load and
// indexes IP→endpoint for the promiscuous WG forwarder. Postgres
// uses this today; clickhouse_native and any future binary protocols
// plug in the same way without main needing to know about them.

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/denoland/clawpatrol/config"
)

// ConnRouter is the optional interface an endpoint plugin's body
// implements when its traffic arrives as raw conns (not via SNI). The
// returned strings are the host[:port] tuples the endpoint claims.
type ConnRouter interface {
	ConnRouteHosts() []string
}

// ConnIndex maps the WG forwarder's dstIP back to the endpoint(s)
// that own it. Multiple endpoints can share an IP (e.g. pg-writer /
// pg-readonly pointing at the same RDS host); the caller filters by
// profile to pick the one the device should use.
type ConnIndex struct {
	byIP   map[string][]*config.CompiledEndpoint
	byHost map[string][]*config.CompiledEndpoint // host:port too, for direct-IP configs
}

// BuildConnIndex walks every endpoint whose body implements ConnRouter
// and resolves each declared host. DNS failures are logged + skipped;
// the endpoint stays in the policy and the caller's per-profile
// fallback (e.g. firstPostgresEndpoint) can still pick it up.
// Resolution is best-effort with a short timeout to avoid stalling
// boot when an upstream is unreachable.
func BuildConnIndex(policy *config.CompiledPolicy) *ConnIndex {
	idx := &ConnIndex{
		byIP:   map[string][]*config.CompiledEndpoint{},
		byHost: map[string][]*config.CompiledEndpoint{},
	}
	if policy == nil {
		return idx
	}
	resolver := &net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var mu sync.Mutex
	appendUnique := func(m map[string][]*config.CompiledEndpoint, k string, ep *config.CompiledEndpoint) {
		for _, e := range m[k] {
			if e == ep {
				return
			}
		}
		m[k] = append(m[k], ep)
	}
	for _, ep := range policy.Endpoints {
		router, ok := ep.Body.(ConnRouter)
		if !ok {
			continue
		}
		ep := ep
		for _, hostport := range router.ConnRouteHosts() {
			host := hostport
			if h, _, err := net.SplitHostPort(hostport); err == nil {
				host = h
			}
			mu.Lock()
			appendUnique(idx.byHost, hostport, ep)
			appendUnique(idx.byHost, host, ep)
			mu.Unlock()
			wg.Add(1)
			go func(host string) {
				defer wg.Done()
				ips, err := resolver.LookupHost(ctx, host)
				if err != nil {
					log.Printf("conn-index resolve %s: %v", host, err)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				for _, ip := range ips {
					appendUnique(idx.byIP, ip, ep)
				}
			}(host)
		}
	}
	wg.Wait()
	return idx
}

// Lookup returns every endpoint that claims dstIP. Order is non-
// deterministic — the caller must do its own selection rather than
// treating index order as meaningful.
func (idx *ConnIndex) Lookup(dstIP string) []*config.CompiledEndpoint {
	if idx == nil {
		return nil
	}
	if eps := idx.byIP[dstIP]; len(eps) > 0 {
		return eps
	}
	if eps := idx.byHost[dstIP]; len(eps) > 0 {
		return eps
	}
	var out []*config.CompiledEndpoint
	for hp, eps := range idx.byHost {
		if strings.HasPrefix(hp, dstIP+":") {
			out = append(out, eps...)
		}
	}
	return out
}
