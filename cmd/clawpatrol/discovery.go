package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/plugins/endpoints"
)

// discoveryHostname is the reserved name an agent inside the tunnel
// hits to learn what its profile can reach. The gateway intercepts a
// TLS connection whose SNI is this name and answers locally — the
// request never leaves the box. DNS for the name resolves to the
// reserved VIP pair the dnsvip allocator hands back (see dnsvip's
// DiscoveryV4/DiscoveryV6), but because the WG forwarder routes every
// :443 SYN through g.handle regardless of dst IP, any IP the agent was
// handed lands here as long as the SNI matches.
const discoveryHostname = "clawpatrol"

// isDiscoveryHost reports whether host names the reserved discovery
// endpoint. The match is case-insensitive (DNS is) and tolerates a
// trailing dot and an explicit :443 suffix, both of which clients may
// attach to the authority.
func isDiscoveryHost(host string) bool {
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == discoveryHostname
}

// serveDiscovery terminates TLS for a reserved-name connection and
// answers it with the caller's profile manifest. The profile is
// resolved from the connection's peer IP (the same connection-derived
// identity the request handler uses) — never from a token — so the
// manifest reflects exactly this device's grants. certHost is the SNI
// (or the dst VIP on the IP-literal fallback path); we mint a leaf for
// it so the agent's CA-trusting client accepts the handshake.
func (g *Gateway) serveDiscovery(c net.Conn, certHost string) {
	defer func() { _ = c.Close() }()
	defer otelTrackConn("discovery")()
	profile := g.profileFor(peerIP(c))
	cert, err := g.certs.mint(certHost)
	if err != nil {
		log.Printf("discovery: mint %s: %v", certHost, err)
		return
	}
	tc := tls.Server(c, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tc.Handshake(); err != nil {
		log.Printf("discovery: tls %s: %v", certHost, err)
		return
	}
	defer func() { _ = tc.Close() }()
	policy := g.Policy()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeDiscoveryResponse(w, r, policy, profile)
	})
	_ = http.Serve(&oneShotListener{c: tc}, h)
}

// isDiscoveryVIP reports whether dstIP is the fixed VIP the dnsvip
// allocator reserves for the discovery name — the signal the IP-literal
// fallback path keys on when there's no SNI.
func (g *Gateway) isDiscoveryVIP(dstIP string) bool {
	if g.dnsvip == nil {
		return false
	}
	addr, err := netip.ParseAddr(dstIP)
	if err != nil {
		return false
	}
	v4, v6 := g.dnsvip.DiscoveryVIPs()
	return addr == v4 || addr == v6
}

// DiscoveryManifest is the one internal representation both output
// formats render from. It describes, scoped to a single device
// profile, exactly which endpoints and credentials the caller can use
// and how to reach each one. It is computed live from the calling
// device's current profile — it is NOT a dump of the whole gateway
// config.
type DiscoveryManifest struct {
	Profile     string                `json:"profile"`
	Endpoints   []DiscoveryEndpoint   `json:"endpoints"`
	Credentials []DiscoveryCredential `json:"credentials"`
	// Notes carries profile-level caveats — e.g. the profile resolved
	// to a name with no policy entry, so the manifest is empty.
	Notes []string `json:"notes,omitempty"`
}

// DiscoveryEndpoint is one reachable endpoint plus the full how-to for
// connecting to it: protocol/type, host(s)/port(s), database/path
// where applicable, and the credential(s) the profile can present.
//
// Deliberately omits any tunnel the endpoint sits behind. The gateway
// intercepts the agent's connection transparently and brings the tunnel
// up itself — the agent dials the host below either way and can't act on
// the tunnel's name or type, so reporting it would only be noise.
type DiscoveryEndpoint struct {
	Name        string                   `json:"name"`
	Type        string                   `json:"type"`   // plugin type: https, postgres, kubernetes, ...
	Family      string                   `json:"family"` // http | sql | k8s | ssh
	Hosts       []string                 `json:"hosts,omitempty"`
	Port        int                      `json:"port,omitempty"`
	Database    string                   `json:"database,omitempty"`
	SSLMode     string                   `json:"sslmode,omitempty"`
	Path        string                   `json:"path,omitempty"`
	Credentials []DiscoveryCredentialRef `json:"credentials"`
	// Hint is a concrete client invocation when the protocol makes one
	// unambiguous (psql / kubectl / clickhouse-client / ssh / curl).
	Hint string `json:"hint,omitempty"`
}

// DiscoveryCredentialRef is a credential the profile can present at a
// specific endpoint. Placeholder is the literal string the agent sends
// where a secret would go (the gateway swaps it for the real secret);
// Disambiguators carries non-placeholder dispatch fields (postgres /
// clickhouse user + database) so the agent connects with the values
// that route to this credential.
type DiscoveryCredentialRef struct {
	Name           string            `json:"name"`
	Type           string            `json:"type"`
	Placeholder    string            `json:"placeholder,omitempty"`
	Disambiguators map[string]string `json:"disambiguators,omitempty"`
}

// DiscoveryCredential is the profile-level view of one credential: its
// type, placeholder, and the endpoints it authenticates against that
// this profile can reach.
type DiscoveryCredential struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Placeholder string   `json:"placeholder,omitempty"`
	Endpoints   []string `json:"endpoints,omitempty"`
}

// buildDiscoveryManifest computes the manifest for one profile from the
// compiled policy. It reuses the same per-profile resolution the
// request handler walks — CompiledProfile.Endpoints and
// EndpointCredentials — so the manifest reports exactly what dispatch
// would honor, nothing more. A profile name with no policy entry (the
// default-profile fallback for an unrecognised device) yields an empty
// manifest with an explanatory note rather than an error.
func buildDiscoveryManifest(policy *config.CompiledPolicy, profileName string) *DiscoveryManifest {
	m := &DiscoveryManifest{Profile: profileName, Endpoints: []DiscoveryEndpoint{}, Credentials: []DiscoveryCredential{}}
	if policy == nil {
		m.Notes = append(m.Notes, "gateway has no compiled policy loaded")
		return m
	}
	prof := policy.Profiles[profileName]
	if prof == nil {
		m.Notes = append(m.Notes, fmt.Sprintf("profile %q grants no endpoints or credentials", profileName))
		return m
	}

	// Endpoints, in a stable name order so the manifest is byte-stable
	// across calls (agents may diff it; tests assert on it).
	names := make([]string, 0, len(prof.Endpoints))
	for name := range prof.Endpoints {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ep := prof.Endpoints[name]
		if ep == nil {
			continue
		}
		de := describeEndpoint(ep)
		de.Credentials = profileEndpointCredentials(prof, name)
		if len(de.Credentials) == 0 {
			// Reachable in this profile but no credential dispatches to
			// it — the agent should know the boundary instead of
			// flailing with an endpoint it can't authenticate to.
			de.Credentials = []DiscoveryCredentialRef{}
		}
		de.Hint = connectionHint(de)
		m.Endpoints = append(m.Endpoints, de)
	}

	// Credentials: what the profile HAS. Endpoints listed per credential
	// are intersected with the profile's reachable set so the agent sees
	// the boundary, not the whole config.
	for _, ent := range prof.Credentials {
		if ent == nil || ent.Symbol == nil {
			continue
		}
		dc := DiscoveryCredential{Name: ent.Symbol.Name}
		if ent.Plugin != nil {
			dc.Type = ent.Plugin.Type
		}
		dc.Placeholder = ent.Framework.Str("placeholder")
		var eps []string
		for _, target := range config.CredentialEndpointTargets(ent) {
			if _, ok := prof.Endpoints[target]; ok {
				eps = append(eps, target)
			}
		}
		sort.Strings(eps)
		dc.Endpoints = eps
		m.Credentials = append(m.Credentials, dc)
	}
	sort.Slice(m.Credentials, func(i, j int) bool { return m.Credentials[i].Name < m.Credentials[j].Name })
	return m
}

// describeEndpoint extracts the connection how-to from a compiled
// endpoint by type-asserting its plugin Body. Unknown plugin types
// fall back to the declared Hosts and plugin type — a new endpoint
// plugin still surfaces in the manifest with its hosts, just without
// type-specific fields.
func describeEndpoint(ep *config.CompiledEndpoint) DiscoveryEndpoint {
	de := DiscoveryEndpoint{Name: ep.Name, Family: ep.Family}
	if ep.Plugin != nil {
		de.Type = ep.Plugin.Type
	}

	switch body := ep.Body.(type) {
	case *endpoints.HTTPSEndpoint:
		de.Hosts = body.Hosts
	case *endpoints.ClickhouseHTTPSEndpoint:
		de.Hosts = body.Hosts
	case *endpoints.PostgresEndpoint:
		host, port := splitHostPort(body.Host, 5432)
		de.Hosts = []string{host}
		de.Port = port
		de.SSLMode = body.SSLMode
	case *endpoints.ClickhouseNativeEndpoint:
		port := body.Port
		if port == 0 {
			port = 9000
			if body.TLS {
				port = 9440
			}
		}
		de.Port = port
		hosts := make([]string, 0, len(body.Hosts))
		for _, h := range body.Hosts {
			hp, _ := splitHostPort(h, port)
			hosts = append(hosts, hp)
		}
		de.Hosts = hosts
	case *endpoints.KubernetesEndpoint:
		de.Hosts = body.EndpointHosts()
		if body.Server != "" {
			// server may be a full URL; surface its path component so
			// the agent points kubectl at the right apiserver path.
			if i := strings.Index(body.Server, "/"); i >= 0 && strings.Contains(body.Server, "://") {
				if u := strings.SplitN(body.Server, "://", 2); len(u) == 2 {
					if j := strings.Index(u[1], "/"); j >= 0 {
						de.Path = u[1][j:]
					}
				}
			}
		}
	case *endpoints.SSHEndpoint:
		hosts := make([]string, 0, len(body.Hosts))
		for _, h := range body.Hosts {
			hp, port := splitHostPort(h, 22)
			hosts = append(hosts, hp)
			de.Port = port
		}
		de.Hosts = hosts
	default:
		// Unknown plugin: best-effort hosts via the generic accessor.
		if hoster, ok := ep.Body.(interface{ EndpointHosts() []string }); ok {
			de.Hosts = hoster.EndpointHosts()
		} else {
			de.Hosts = ep.Hosts
		}
	}
	if len(de.Hosts) == 0 {
		de.Hosts = ep.Hosts
	}
	return de
}

// profileEndpointCredentials returns the credentials the profile can
// present at endpointName, with placeholder + dispatch discriminators
// pulled from the profile-scoped dispatch table (the same table
// runtime.ResolveCredential consults).
func profileEndpointCredentials(prof *config.CompiledProfile, endpointName string) []DiscoveryCredentialRef {
	ccs := prof.EndpointCredentials[endpointName]
	out := make([]DiscoveryCredentialRef, 0, len(ccs))
	for _, cc := range ccs {
		if cc == nil || cc.Credential == nil || cc.Credential.Symbol == nil {
			continue
		}
		ref := DiscoveryCredentialRef{Name: cc.Credential.Symbol.Name}
		if cc.Credential.Plugin != nil {
			ref.Type = cc.Credential.Plugin.Type
		}
		// Split the merged disambiguator map into the placeholder (the
		// literal the agent sends) and the rest (postgres/clickhouse
		// user + database the agent connects with).
		if len(cc.Disambiguators) > 0 {
			rest := map[string]string{}
			for k, v := range cc.Disambiguators {
				if k == "placeholder" {
					ref.Placeholder = v
					continue
				}
				rest[k] = v
			}
			if len(rest) > 0 {
				ref.Disambiguators = rest
			}
		}
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// splitHostPort splits a "host:port" string, falling back to def when
// no port is present. Bare hosts and bracketed IPv6 are both handled.
func splitHostPort(hp string, def int) (string, int) {
	if hp == "" {
		return "", def
	}
	host, portStr, err := net.SplitHostPort(hp)
	if err != nil {
		return hp, def
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, def
	}
	return host, port
}

// connectionHint returns a concrete client invocation for the endpoint
// where the protocol makes one unambiguous. Empty when there's no
// single obvious command (the agent still has hosts/port/credential).
func connectionHint(de DiscoveryEndpoint) string {
	host := ""
	if len(de.Hosts) > 0 {
		host = de.Hosts[0]
	}
	if host == "" {
		return ""
	}
	switch de.Type {
	case "postgres":
		var b strings.Builder
		fmt.Fprintf(&b, "psql \"host=%s port=%d", host, de.Port)
		if user := firstDisambiguator(de, "user"); user != "" {
			fmt.Fprintf(&b, " user=%s", user)
		}
		if db := firstDisambiguator(de, "database"); db != "" {
			fmt.Fprintf(&b, " dbname=%s", db)
		} else if de.Database != "" {
			fmt.Fprintf(&b, " dbname=%s", de.Database)
		}
		if de.SSLMode != "" {
			fmt.Fprintf(&b, " sslmode=%s", de.SSLMode)
		}
		b.WriteString("\"")
		return b.String()
	case "clickhouse_native":
		hint := fmt.Sprintf("clickhouse-client --host %s --port %d", host, de.Port)
		if user := firstDisambiguator(de, "user"); user != "" {
			hint += " --user " + user
		}
		if db := firstDisambiguator(de, "database"); db != "" {
			hint += " --database " + db
		}
		return hint
	case "kubernetes":
		return fmt.Sprintf("kubectl --server https://%s%s ...", host, de.Path)
	case "ssh":
		user := firstDisambiguator(de, "user")
		if user != "" {
			return fmt.Sprintf("ssh %s@%s", user, host)
		}
		return fmt.Sprintf("ssh %s", host)
	case "https", "clickhouse_https":
		ph := firstPlaceholder(de)
		if ph != "" {
			return fmt.Sprintf("curl https://%s/ -H \"Authorization: Bearer %s\"", host, ph)
		}
		return fmt.Sprintf("curl https://%s/", host)
	}
	return ""
}

// firstPlaceholder returns the placeholder of the first credential
// bound at the endpoint that has one.
func firstPlaceholder(de DiscoveryEndpoint) string {
	for _, c := range de.Credentials {
		if c.Placeholder != "" {
			return c.Placeholder
		}
	}
	return ""
}

// firstDisambiguator returns the value of key from the first
// credential at the endpoint that carries it.
func firstDisambiguator(de DiscoveryEndpoint, key string) string {
	for _, c := range de.Credentials {
		if v := c.Disambiguators[key]; v != "" {
			return v
		}
	}
	return ""
}

// Markdown renders the manifest as an agent-readable document
// (llms.txt style). An LLM consumes this directly, so it leads with
// orientation and keeps each endpoint's how-to self-contained.
func (m *DiscoveryManifest) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Claw Patrol access manifest — profile: %s\n\n", m.Profile)
	b.WriteString("You are connected through the Claw Patrol gateway. It intercepts your\n")
	b.WriteString("connections transparently: dial the hosts below as you normally would and\n")
	b.WriteString("the gateway injects credentials and enforces policy. A credential\n")
	b.WriteString("`placeholder` is a literal string you send where the secret would go — the\n")
	b.WriteString("gateway swaps it for the real secret. This manifest is scoped to YOUR\n")
	b.WriteString("device profile; it lists only what this profile grants.\n\n")

	for _, n := range m.Notes {
		fmt.Fprintf(&b, "> Note: %s\n\n", n)
	}

	fmt.Fprintf(&b, "## Endpoints (%d)\n\n", len(m.Endpoints))
	if len(m.Endpoints) == 0 {
		b.WriteString("_None reachable for this profile._\n\n")
	}
	for _, ep := range m.Endpoints {
		fmt.Fprintf(&b, "### %s  (%s)\n\n", ep.Name, ep.Type)
		if len(ep.Hosts) > 0 {
			fmt.Fprintf(&b, "- Host(s): %s\n", strings.Join(ep.Hosts, ", "))
		}
		if ep.Port != 0 {
			fmt.Fprintf(&b, "- Port: %d\n", ep.Port)
		}
		if ep.Database != "" {
			fmt.Fprintf(&b, "- Database: %s\n", ep.Database)
		}
		if ep.SSLMode != "" {
			fmt.Fprintf(&b, "- SSL mode: %s\n", ep.SSLMode)
		}
		if ep.Path != "" {
			fmt.Fprintf(&b, "- Path: %s\n", ep.Path)
		}
		if len(ep.Credentials) == 0 {
			b.WriteString("- Credential: NONE bound for this profile — you cannot authenticate here\n")
		}
		for _, c := range ep.Credentials {
			line := fmt.Sprintf("- Credential: %s `%s`", c.Type, c.Name)
			if c.Placeholder != "" {
				line += fmt.Sprintf(" — send placeholder `%s`", c.Placeholder)
			}
			if len(c.Disambiguators) > 0 {
				line += " — connect with " + joinDisambiguators(c.Disambiguators)
			}
			b.WriteString(line + "\n")
		}
		if ep.Hint != "" {
			fmt.Fprintf(&b, "- Example: `%s`\n", ep.Hint)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Credentials (%d)\n\n", len(m.Credentials))
	if len(m.Credentials) == 0 {
		b.WriteString("_None granted to this profile._\n")
	}
	for _, c := range m.Credentials {
		line := fmt.Sprintf("- %s `%s`", c.Type, c.Name)
		if c.Placeholder != "" {
			line += fmt.Sprintf(" → placeholder `%s`", c.Placeholder)
		}
		if len(c.Endpoints) > 0 {
			line += " → endpoints: " + strings.Join(c.Endpoints, ", ")
		} else {
			line += " → (no reachable endpoint in this profile)"
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// joinDisambiguators renders a "key=value" set in stable key order.
func joinDisambiguators(d map[string]string) string {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, d[k]))
	}
	return strings.Join(parts, " ")
}

// wantsJSON decides the response format. An explicit `?format=json`
// (or `format=markdown`) query param wins; otherwise the Accept header
// picks. Default is markdown — the primary consumer is an LLM.
func wantsJSON(r *http.Request) bool {
	switch strings.ToLower(r.URL.Query().Get("format")) {
	case "json":
		return true
	case "markdown", "md", "text":
		return false
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/markdown") {
		return true
	}
	return false
}

// writeDiscoveryResponse renders the manifest for profileName in the
// format the request asked for. Factored out of the TLS-serving path
// so it can be exercised with httptest without standing up WireGuard.
func writeDiscoveryResponse(w http.ResponseWriter, r *http.Request, policy *config.CompiledPolicy, profileName string) {
	m := buildDiscoveryManifest(policy, profileName)
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(m)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	_, _ = w.Write([]byte(m.Markdown()))
}
