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
	byIP   map[string]*config.CompiledEndpoint
	byHost map[string]*config.CompiledEndpoint // host:port too, for direct-IP configs
}

// buildPgIndex walks the policy's postgres endpoints and resolves
// each declared host. DNS failures are logged + skipped (the
// endpoint stays in the policy; firstPostgresEndpoint catches it as
// a fallback). Resolution is best-effort with a short timeout to
// avoid stalling boot when an upstream is unreachable.
func buildPgIndex(policy *config.CompiledPolicy) *pgIndex {
	idx := &pgIndex{
		byIP:   map[string]*config.CompiledEndpoint{},
		byHost: map[string]*config.CompiledEndpoint{},
	}
	if policy == nil {
		return idx
	}
	resolver := &net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var mu sync.Mutex
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
			idx.byHost[hostport] = ep
			idx.byHost[host] = ep
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
					idx.byIP[ip] = ep
				}
			}(host)
		}
	}
	wg.Wait()
	return idx
}

// lookup returns the postgres endpoint for a destination IP (the WG
// forwarder's view), falling back to host-string matching for
// configs that pin an IP directly in the host field.
func (idx *pgIndex) lookup(dstIP string) *config.CompiledEndpoint {
	if idx == nil {
		return nil
	}
	if ep := idx.byIP[dstIP]; ep != nil {
		return ep
	}
	// Direct-IP configs: the host field is itself an IP.
	if ep := idx.byHost[dstIP]; ep != nil {
		return ep
	}
	// host:port direct-IP configs.
	for hp, ep := range idx.byHost {
		if strings.HasPrefix(hp, dstIP+":") {
			return ep
		}
	}
	return nil
}
