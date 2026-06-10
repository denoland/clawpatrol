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

// internalHostname is the reserved name an agent inside the tunnel
// hits to reach the clawpatrol API — the canonical entrypoint for a
// device. The gateway intercepts a TLS connection whose SNI is this
// name and answers locally — the request never leaves the box. DNS for
// the name resolves to the reserved VIP pair the dnsvip allocator hands
// back (see dnsvip's InternalVIPs), but because the WG forwarder routes
// every :443 SYN through g.handle regardless of dst IP, any IP the
// agent was handed lands here as long as the SNI matches. Keep this in
// sync with dnsvip.InternalHostname.
const internalHostname = "clawpatrol.internal"

// isInternalHost reports whether host names the reserved internal API
// endpoint. The match is case-insensitive (DNS is) and tolerates a
// trailing dot and an explicit :443 suffix, both of which clients may
// attach to the authority.
func isInternalHost(host string) bool {
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == internalHostname
}

// serveInternal terminates TLS for a reserved-name connection and
// answers it from the internal API surface (manifest, CA, info). The
// profile is resolved from the connection's peer IP (the same
// connection-derived identity the request handler uses) — never from a
// token — so the manifest reflects exactly this device's grants.
// certHost is the SNI (or the dst VIP on the IP-literal fallback path);
// we mint a leaf for it so the agent's CA-trusting client accepts the
// handshake.
func (g *Gateway) serveInternal(c net.Conn, certHost string) {
	defer func() { _ = c.Close() }()
	defer otelTrackConn("internal")()
	profile := g.profileFor(peerIP(c))
	cert, err := g.certs.mint(certHost)
	if err != nil {
		log.Printf("internal: mint %s: %v", certHost, err)
		return
	}
	tc := tls.Server(c, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tc.Handshake(); err != nil {
		log.Printf("internal: tls %s: %v", certHost, err)
		return
	}
	defer func() { _ = tc.Close() }()
	policy := g.Policy()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.routeInternal(w, r, policy, profile)
	})
	_ = http.Serve(&oneShotListener{c: tc}, h)
}

// routeInternal dispatches a request to the in-tunnel internal API
// entrypoint by path. clawpatrol.internal is the canonical device-facing
// API surface, so it exposes the profile manifest at / and /manifest,
// the gateway CA at /ca.crt, and a liveness + CA-fingerprint blob at
// /info — the same public endpoints the gateway's tailnet web server
// serves, mirrored here so a device with only tunnel reachability can
// fetch them by name. Unknown paths 404 rather than falling through to
// the manifest, so the canonical paths stay unambiguous.
func (g *Gateway) routeInternal(w http.ResponseWriter, r *http.Request, policy *config.CompiledPolicy, profile string) {
	switch r.URL.Path {
	case "/", "/manifest":
		writeDiscoveryResponse(w, r, policy, profile)
	case "/ca.crt":
		g.serveInternalCA(w)
	case "/info":
		g.serveInternalInfo(w)
	default:
		http.NotFound(w, r)
	}
}

// serveInternalCA returns the gateway CA in PEM form at
// clawpatrol.internal/ca.crt. A client that trusts neither the system
// store nor the pushed-down CA env vars can fetch the CA here and pin it
// explicitly — the manifest text points at this path. Mirrors the
// gateway web server's public /ca.crt (web.go serveCA).
func (g *Gateway) serveInternalCA(w http.ResponseWriter) {
	pemBytes := g.certs.CertPEM()
	if len(pemBytes) == 0 {
		http.Error(w, "ca not initialized", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Length", strconv.Itoa(len(pemBytes)))
	_, _ = w.Write(pemBytes)
}

// serveInternalInfo answers clawpatrol.internal/info with a small
// liveness + identity blob carrying the CA fingerprint, so a client can
// verify the CA it fetched from /ca.crt against an out-of-band value.
// Mirrors the gateway web server's public /info (web.go serveInfo).
func (g *Gateway) serveInternalInfo(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fp := ""
	if pem := g.certs.CertPEM(); len(pem) > 0 {
		if f, err := caFingerprintFromPEM(pem); err == nil {
			fp = f
		}
	}
	writeJSON(w, map[string]any{
		"clawpatrol":     true,
		"version":        "0.1",
		"ca_fingerprint": fp,
	})
}

// isInternalVIP reports whether dstIP is the fixed VIP the dnsvip
// allocator reserves for the internal API name — the signal the
// IP-literal fallback path keys on when there's no SNI.
func (g *Gateway) isInternalVIP(dstIP string) bool {
	if g.dnsvip == nil {
		return false
	}
	addr, err := netip.ParseAddr(dstIP)
	if err != nil {
		return false
	}
	v4, v6 := g.dnsvip.InternalVIPs()
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
	// EnvVars lists the environment variables `clawpatrol run` pushes
	// into the agent's process environment for THIS profile — the same
	// set the env-pushdown API serves. An agent reads its credential
	// out of one of these vars without ever seeing the real secret, so
	// it needs to know which of its env vars the gateway controls and
	// what each one carries.
	EnvVars []DiscoveryEnvVar `json:"env_vars"`
	// Notes carries profile-level caveats — e.g. the profile resolved
	// to a name with no policy entry, so the manifest is empty.
	Notes []string `json:"notes,omitempty"`
	// Dashboard is the gateway's public URL (gateway.public_url), where a
	// human operator configures this device's profile. Surfaced so an
	// agent whose profile grants nothing can tell its human where to go.
	// Empty when public_url is unset.
	Dashboard string `json:"dashboard,omitempty"`
}

// isEmpty reports whether the profile grants nothing — no endpoints and
// no credentials. This is the state the empty-profile guidance speaks
// to: a manifest that lists nothing actionable is useless to an agent
// unless it explains why and how to fix it.
func (m *DiscoveryManifest) isEmpty() bool {
	return len(m.Endpoints) == 0 && len(m.Credentials) == 0
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
	Name   string `json:"name"`
	Type   string `json:"type"`   // plugin type: https, postgres, kubernetes, ...
	Family string `json:"family"` // http | sql | k8s | ssh
	// Description is the operator's free-text note from the endpoint
	// block's `description = "..."`, surfaced to orient the agent.
	Description string                   `json:"description,omitempty"`
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
	// Description is the operator's free-text note from the credential
	// block's `description = "..."`, surfaced to orient the agent.
	Description string `json:"description,omitempty"`
}

// DiscoveryCredential is the profile-level view of one credential: its
// type, placeholder, and the endpoints it authenticates against that
// this profile can reach.
type DiscoveryCredential struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Placeholder string   `json:"placeholder,omitempty"`
	Endpoints   []string `json:"endpoints,omitempty"`
	// Description is the operator's free-text note from the credential
	// block's `description = "..."`, surfaced to orient the agent.
	Description string `json:"description,omitempty"`
}

// DiscoveryEnvVar is one environment variable `clawpatrol run` exports
// into the agent's process so its CLI/SDK finds its credential without
// the agent ever holding the real secret. Value is the literal the
// gateway sets — a placeholder that LOOKS like a real token (swapped
// for the secret at MITM time) or a synthetic token — NOT the secret
// itself. Type is the credential/endpoint plugin that pushes it.
type DiscoveryEnvVar struct {
	Name        string `json:"name"`
	Value       string `json:"value,omitempty"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type,omitempty"`
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
		m.Dashboard = policy.DashboardURL
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
		dc := DiscoveryCredential{Name: ent.Symbol.Name, Description: ent.Framework.Str("description")}
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

	// Env vars pushed into the agent's process for this profile — the
	// same union the env-pushdown API serves, scoped here too.
	m.EnvVars = buildDiscoveryEnvVars(prof)

	// A profile that grants nothing leaves the agent with nothing to act
	// on; surface the dashboard URL so it can point its human at where the
	// device's profile gets configured. Non-empty manifests already carry
	// everything actionable, so the pointer would just be noise there.
	if m.isEmpty() {
		m.Dashboard = policy.DashboardURL
	}
	return m
}

// buildDiscoveryEnvVars collects the environment variables this profile
// pushes into the agent's process, mirroring the env-pushdown API
// (apiEnvPushdown): walk every endpoint the profile reaches, take the
// EnvVars() of each bound credential first (credential-shaped values
// win on a name clash) and of each endpoint plugin second, deduping by
// variable name. Endpoints are visited in sorted order so the result is
// byte-stable across calls — agents may diff this manifest and the
// golden tests assert on it.
//
// CA-bundle vars (SSL_CERT_FILE and friends) are deliberately excluded:
// they point at a path on the client's disk, the env-pushdown API omits
// them for the same reason, and the manifest's intro already explains
// the CA installation.
func buildDiscoveryEnvVars(prof *config.CompiledProfile) []DiscoveryEnvVar {
	out := []DiscoveryEnvVar{}
	if prof == nil {
		return out
	}
	seen := map[string]bool{}
	add := func(name, value, description, pluginType string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, DiscoveryEnvVar{Name: name, Value: value, Description: description, Type: pluginType})
	}

	names := make([]string, 0, len(prof.Endpoints))
	for name := range prof.Endpoints {
		names = append(names, name)
	}
	sort.Strings(names)

	// Credentials first, so a credential's placeholder wins over an
	// endpoint plugin that happens to push the same variable name.
	credSeen := map[string]bool{}
	for _, name := range names {
		ep := prof.Endpoints[name]
		if ep == nil {
			continue
		}
		for _, ent := range ep.Credentials {
			if ent == nil || ent.Symbol == nil || ent.Plugin == nil || credSeen[ent.Symbol.Name] {
				continue
			}
			credSeen[ent.Symbol.Name] = true
			provider, ok := ent.Body.(config.EnvPushdownProvider)
			if !ok {
				continue
			}
			for _, ev := range provider.EnvVars() {
				add(ev.Name, ev.Value, ev.Description, ent.Plugin.Type)
			}
		}
	}
	// Endpoint plugins second (e.g. openai_codex_https pushes its own).
	for _, name := range names {
		ep := prof.Endpoints[name]
		if ep == nil || ep.Plugin == nil {
			continue
		}
		provider, ok := ep.Body.(config.EnvPushdownProvider)
		if !ok {
			continue
		}
		for _, ev := range provider.EnvVars() {
			add(ev.Name, ev.Value, ev.Description, ep.Plugin.Type)
		}
	}
	return out
}

// describeEndpoint extracts the connection how-to from a compiled
// endpoint by type-asserting its plugin Body. Unknown plugin types
// fall back to the declared Hosts and plugin type — a new endpoint
// plugin still surfaces in the manifest with its hosts, just without
// type-specific fields.
func describeEndpoint(ep *config.CompiledEndpoint) DiscoveryEndpoint {
	de := DiscoveryEndpoint{Name: ep.Name, Family: ep.Family, Description: ep.Description}
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
		ref := DiscoveryCredentialRef{
			Name:        cc.Credential.Symbol.Name,
			Description: cc.Credential.Framework.Str("description"),
		}
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

	b.WriteString("TLS is intercepted only for the hosts this profile grants — the\n")
	b.WriteString("endpoints listed below. For those, the gateway terminates TLS and acts\n")
	b.WriteString("as a transparent man-in-the-middle: the certificate you see is minted on\n")
	b.WriteString("the fly by Claw Patrol's own certificate authority, not the host's real\n")
	b.WriteString("public certificate. The hostname matches but the issuer is the gateway\n")
	b.WriteString("CA. You normally don't have to do anything to trust it: Claw Patrol\n")
	b.WriteString("already installed its CA on this device when you joined — both in the\n")
	b.WriteString("system trust store and via environment-variable pushdown\n")
	b.WriteString("(SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE,\n")
	b.WriteString("and similar) that `clawpatrol run` sets for the processes it wraps. So\n")
	b.WriteString("most clients validate these connections out of the box, and a\n")
	b.WriteString("certificate-authority mismatch against the public web PKI is expected\n")
	b.WriteString("for these hosts, not an attack. If a client ignores both the system\n")
	b.WriteString("store and those env vars, fetch the CA from\n")
	b.WriteString("https://clawpatrol.internal/ca.crt, verify its fingerprint against\n")
	b.WriteString("https://clawpatrol.internal/info, and point that\n")
	b.WriteString("client at it explicitly.\n\n")

	b.WriteString("Every other host is passed through untouched: the gateway does not\n")
	b.WriteString("intercept it, you get the upstream's real certificate, and you must\n")
	b.WriteString("still verify it against the public web PKI as usual.\n\n")

	for _, n := range m.Notes {
		fmt.Fprintf(&b, "> Note: %s\n\n", n)
	}

	if m.isEmpty() {
		b.WriteString(m.emptyGuidance())
	}

	fmt.Fprintf(&b, "## Endpoints (%d)\n\n", len(m.Endpoints))
	if len(m.Endpoints) == 0 {
		b.WriteString("_None reachable for this profile._\n\n")
	}
	for _, ep := range m.Endpoints {
		fmt.Fprintf(&b, "### %s  (%s)\n\n", ep.Name, ep.Type)
		if ep.Description != "" {
			fmt.Fprintf(&b, "%s\n\n", ep.Description)
		}
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
			if c.Description != "" {
				line += fmt.Sprintf(" — %s", c.Description)
			}
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

	fmt.Fprintf(&b, "## Environment variables (%d)\n\n", len(m.EnvVars))
	if len(m.EnvVars) == 0 {
		b.WriteString("_None pushed for this profile._\n\n")
	} else {
		b.WriteString("`clawpatrol run` sets these in your process environment so your CLI/SDK\n")
		b.WriteString("finds its credential automatically. The value shown is what the gateway\n")
		b.WriteString("exports — a placeholder that looks like a real token (swapped for the\n")
		b.WriteString("real secret at request time) or a synthetic token, never the secret\n")
		b.WriteString("itself. You don't need to set these yourself; this is what is already\n")
		b.WriteString("in your environment.\n\n")
		for _, ev := range m.EnvVars {
			line := fmt.Sprintf("- `%s`", ev.Name)
			if ev.Value != "" {
				line += fmt.Sprintf(" = `%s`", ev.Value)
			}
			if ev.Description != "" {
				line += fmt.Sprintf(" — %s", ev.Description)
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n")
	}

	return b.String()
}

// emptyGuidance is the block rendered when a profile grants nothing. A
// bare "none reachable / none granted" manifest is dead-on-arrival for
// an agent: it can't tell whether the gateway is broken, whether it's
// the wrong device, or what to do next. This explains that the empty
// result is a configuration state, what unlocks Claw Patrol's value, and
// where the operator changes this device's profile.
func (m *DiscoveryManifest) emptyGuidance() string {
	var b strings.Builder
	b.WriteString("## This profile is empty\n\n")
	fmt.Fprintf(&b, "Your device is mapped to the `%s` profile, which currently grants no\n", m.Profile)
	b.WriteString("endpoints and no credentials. That's why there's nothing actionable\n")
	b.WriteString("below. This is a configuration state, not an error — the gateway is\n")
	b.WriteString("reachable, your device just hasn't been granted anything yet.\n\n")
	b.WriteString("To get value from Claw Patrol, this profile needs endpoints and the\n")
	b.WriteString("credentials to reach them bound to it. An operator does that in the\n")
	b.WriteString("dashboard by either assigning this device a profile that already grants\n")
	b.WriteString("what you need, or adding endpoints and credentials to this one.\n\n")
	if m.Dashboard != "" {
		fmt.Fprintf(&b, "Ask the person who runs this gateway to open the dashboard at %s\n", m.Dashboard)
		b.WriteString("and update this device's profile.\n\n")
	} else {
		b.WriteString("Ask the person who runs this gateway to open the Claw Patrol dashboard\n")
		b.WriteString("and update this device's profile.\n\n")
	}
	b.WriteString("Once the profile is configured, re-fetch this manifest (GET\n")
	b.WriteString("https://clawpatrol.internal/manifest) and the endpoints and credentials\n")
	b.WriteString("will appear below.\n\n")
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
