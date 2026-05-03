package main

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/denoland/clawpatrol-go/config"
)

// pgIndex resolves WG-forwarder dstIPs back to the postgres endpoint
// they belong to. Built at policy-load time by walking every
// postgres-family endpoint, splitting host:port, and resolving the
// host via net.LookupHost. Subsequent lookups are O(1).
//
// Multi-postgres profiles need this — without it firstPostgresEndpoint
// just picks the first postgres in the device's profile, which only
// works when the profile has exactly one. With the index, traffic to
// pg-deployng (cluster A IPs) and pg-scheduler (cluster B IPs)
// dispatches to the right endpoint.
type pgIndex struct {
	byIP   map[string][]*config.CompiledEndpoint
	byHost map[string][]*config.CompiledEndpoint // host:port too, for direct-IP configs
}

// buildPgIndex walks the policy's postgres endpoints and resolves
// each declared host. DNS failures are logged + skipped (the
// endpoint stays in the policy; firstPostgresEndpoint catches it as
// a fallback). Resolution is best-effort with a short timeout to
// avoid stalling boot when an upstream is unreachable.
func buildPgIndex(policy *config.CompiledPolicy) *pgIndex {
	idx := &pgIndex{
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
		if ep.Plugin.Type != "postgres" {
			continue
		}
		ep := ep
		for _, hostport := range ep.Hosts {
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
					log.Printf("pg-index resolve %s: %v", host, err)
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

// lookup returns every postgres endpoint that claims dstIP. Multiple
// endpoints can share an IP (e.g. pg-writer / pg-readonly pointing at
// the same RDS host); the caller filters by profile to pick the one
// the device should use. Order is non-deterministic — the caller
// must do its own selection rather than treating index order as
// meaningful.
func (idx *pgIndex) lookup(dstIP string) []*config.CompiledEndpoint {
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
