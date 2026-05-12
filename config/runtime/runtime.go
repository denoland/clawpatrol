// Package runtime hosts the request-time dispatcher and the plugin
// runtime interfaces. The architecture mirrors unclaw's plugin
// runtime: endpoint plugins own protocol decoding, credential plugins
// own secret injection, approver plugins own arbitration. Built-in
// plugins satisfy these interfaces directly; a future distribution
// layer would slot in behind the same shapes.
package runtime

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/match"
)

// HTTPCredentialRuntime is the credential-plugin contract for HTTP
// auth shapes (bearer / cookie / header / mtls / OAuth-with-bearer).
// Inject mutates req.Header (and maybe req.URL if cookies involve a
// path); the secret string is fetched out-of-band by the host (e.g.
// via clawpatrol's existing OAuthRegistry) and passed in as Secret.
//
// Implementations live next to their config plugin so the schema and
// runtime stay co-located, mirroring unclaw's plugin layout.
type HTTPCredentialRuntime interface {
	InjectHTTP(ctx context.Context, req *http.Request, sec Secret) error
}

// WebSocketCredentialRuntime is the credential-plugin contract for
// server-bound WebSocket text payloads that carry token placeholders.
// The gateway calls this after decoding/unmasking a complete text frame
// but before forwarding it upstream; implementations must return a new
// plaintext payload and indicate whether the frame must be rebuilt.
// Inspectors still receive the original placeholder-bearing payload so
// real secrets are not emitted to logs or the dashboard.
type WebSocketCredentialRuntime interface {
	RewriteWebSocketPayload(ctx context.Context, payload []byte, sec Secret) ([]byte, bool, error)
}

// HTTPSyntheticResponder is the optional contract an endpoint
// plugin's runtime implements when it needs to short-circuit certain
// matched requests and return a synthetic response without forwarding
// upstream. The openai_codex_https endpoint uses it to serve a
// clawpatrol-controlled JWKS at chatgpt.com's agent-identity URL (so
// a JWT we minted ourselves validates) and to stub out the agent-task
// registration POST.
//
// RespondHTTP is called by mitmHTTPS before credential injection.
// Returning (resp, true, nil) writes resp to the agent and skips
// forwarding; returning (_, false, nil) falls through to the normal
// inject + proxy path. Errors are logged and the request still
// forwards verbatim.
//
// The hook lives on the endpoint plugin (not the credential) so the
// behavior is bound to the protocol surface, not to whichever bearer
// happens to be configured for it.
type HTTPSyntheticResponder interface {
	RespondHTTP(ctx context.Context, req *http.Request) (*http.Response, bool, error)
}

// PostgresCredentialRuntime swaps the agent's StartupMessage password
// for the real one before the upstream connect. The wire-protocol
// front-end calls this once per session.
type PostgresCredentialRuntime interface {
	InjectPostgres(ctx context.Context, startup *PostgresStartup, sec Secret) error
}

// PostgresAuthCredential is what the postgres endpoint runtime needs
// from a credential plugin to terminate upstream auth. The credential
// returns its (user, password) — runtime drives the SCRAM / cleartext
// handshake itself, so the agent never sees an auth challenge.
type PostgresAuthCredential interface {
	PostgresAuth(sec Secret) (user, password string)
}

// ClickhouseAuthCredential is what the clickhouse_native endpoint
// runtime needs from a credential plugin to inject secrets into the
// agent's Hello packet. The credential returns its (user, password);
// the runtime swaps placeholder bytes the agent embedded in the
// Hello's username / password slots before forwarding the packet
// upstream. Same shape as PostgresAuth — kept distinct so the
// checker can confirm a credential is wired for the right protocol.
type ClickhouseAuthCredential interface {
	ClickhouseAuth(sec Secret) (user, password string)
}

// TLSCredentialRuntime customizes the upstream TLS configuration
// before the dial. mTLS credentials use this to add a client cert
// (Certificates) and an optional custom root pool (RootCAs); other
// shapes — pinned-cert, ALPN-twiddling — extend via the same hook
// without changing the call site.
//
// Implementations mutate cfg in place. Secret.Extras typically holds
// "cert" / "key" / "ca" PEM blobs; the env-var store populates them
// from CLAWPATROL_SECRET_<NAME>_{CERT,KEY,CA} (with @path/to/file
// shorthand for reading PEM bundles off disk).
type TLSCredentialRuntime interface {
	ConfigureUpstreamTLS(cfg *tls.Config, sec Secret) error
}

// ConnEndpointRuntime owns request-time handling for protocols that
// don't fit the http.Request model — postgres, clickhouse_native,
// any future binary wire protocol. The plugin receives the agent
// connection (post TLS termination if applicable) plus a connect
// callback to dial the upstream, walks the compiled rule list with
// a family-appropriate match.Request, and forwards / denies / pauses
// for approval per the rule's Outcome.
//
// HandleConn returns when the session ends; errors are logged by
// the dispatcher.
type ConnEndpointRuntime interface {
	HandleConn(ctx context.Context, ch *ConnHandle) error
}

// ConnHandle bundles everything a ConnEndpointRuntime needs to
// service one inbound connection. Kept narrow so plugins don't need
// to import the gateway package.
type ConnHandle struct {
	Conn     net.Conn
	Endpoint *config.CompiledEndpoint
	Policy   *config.CompiledPolicy
	// Profile is the device's profile name, looked up from peer IP
	// before dispatch.
	Profile string
	// PeerIP is the agent's source IP, used as the "owner" key when
	// fetching credentials from the secret store.
	PeerIP string
	// Secrets is the host's SecretStore; plugins use it to fetch
	// credential material at session-start time (postgres) or per
	// query (rare).
	Secrets SecretStore
	// DialUpstream connects to the upstream host:port over plain
	// TCP. Postgres MITM uses this for the upstream socket.
	DialUpstream func(ctx context.Context, network, addr string) (net.Conn, error)
	// Sink is an opaque event-sink callback. Plugins emit per-query
	// events; the gateway funnels them to the dashboard SSE +
	// JSONL log.
	Emit func(ev ConnEvent)
	// Approve runs an approve = [...] chain through the host's HITL
	// infrastructure. Plugins call it when a matched rule's
	// Outcome.Approve is non-empty; the host wraps its
	// existing approver registry (dashboard / Slack / LLM) and
	// returns the verdict synchronously. nil when the host doesn't
	// support HITL for this conn family — plugins must default to
	// deny in that case.
	Approve func(req ApproveCallRequest) ApproveVerdict
	// CADir is the gateway's CA / persistent state root (matches
	// cfg.CADir). Endpoint runtimes that need to persist material
	// per endpoint — e.g. SSH host keys at <CADir>/ssh/<name>.key —
	// derive paths from this. Empty when the gateway hasn't been
	// configured with a CA dir; plugins that need persistence error
	// out clearly in that case.
	CADir string
	// DstPort is the destination port the agent connection arrived
	// on (post-VIP / direct dial). Endpoints whose host strings
	// carry a non-default port (`hosts = ["x.com:22222"]`) consult
	// this to pick which Hosts[i] the connection corresponds to.
	DstPort uint16
	// UpstreamHost is the hostname the agent dialed, resolved from
	// the VIP table at dispatch time. Populated for VIP-routed conns
	// only; empty for direct-IP / fixed-port dispatches (postgres).
	// Plugins use it to (a) pass a real hostname to DialUpstream so
	// the gateway's host network can resolve it, and (b) drive SNI /
	// SAN matching when the protocol layers TLS on top.
	UpstreamHost string
	// MintCert returns a leaf certificate signed by the gateway CA
	// for the given hostname (or IP literal). Plugins that
	// TLS-terminate inbound traffic — clickhouse_native with
	// `tls = true`, future binary protocols — call this from a
	// `tls.Config.GetCertificate` callback so the SAN matches the
	// SNI the client sent. nil when the dispatcher can't mint
	// (gateway has no CA).
	MintCert func(host string) (*tls.Certificate, error)
}

// ApproveCallRequest is what a ConnEndpointRuntime hands to
// ConnHandle.Approve when a matched rule has an approve = [...]
// chain. Verb / Summary populate the dashboard's HITL request card;
// Stages drives which approvers fire in which order.
type ApproveCallRequest struct {
	Stages  []config.ApproveStage
	Verb    string // SQL verb / k8s verb / etc., for the dashboard
	Summary string // one-liner the operator sees in the HITL prompt
	// Rule is the matched compiled rule (carries Reason for the
	// dashboard's "why is this gated" line).
	Rule *config.CompiledRule
}

// ConnEvent is the wire-protocol-agnostic event shape conn-family
// plugins emit per request / query.
//
// Facets carries the per-family report payload the host writes to
// Event.Facets — the result of calling the family's facet.Runtime
// Report hook against the matched request. Conn plugins populate it
// when they have the parsed metadata in scope (postgres / clickhouse
// build it from the *sqlfacet.Meta stashed on mreq.Meta) so the
// dashboard doesn't have to round-trip through the legacy
// Verb / Summary squashing.
type ConnEvent struct {
	Action  string // "allow" | "deny" | "hitl_allow" | "hitl_deny" | "error"
	Reason  string
	Verb    string // SQL verb / k8s verb / etc.
	Summary string // human-readable one-liner for the event log
	Bytes   int64  // approximate request size for billing / quotas
	Facets  map[string]any
}

// Secret is what credential plugins receive at injection time. The
// Bytes are the actual secret material; Kind disambiguates what shape
// the credential expects (bearer / api-key / cookie / mTLS bundle /
// postgres password / ...). The host (clawpatrol) fetches the value
// from its existing oauth.go store before calling the plugin.
type Secret struct {
	Kind  string
	Bytes []byte
	// Extras is plugin-specific. mTLS passes cert / key / chain;
	// postgres passes user; OAuth passes refresh token + expiry.
	Extras map[string]string
}

// PostgresStartup is the view a postgres credential plugin sees of
// the StartupMessage it must rewrite. The wire-protocol front-end
// fills it; the credential plugin updates Password + optionally User.
type PostgresStartup struct {
	User     string
	Database string
	Password string
}

// HITLNotifier is the optional interface a credential plugin
// implements when it can deliver a HITL approval prompt to a human
// (Slack chat.postMessage, Discord webhook, Telegram sendMessage,
// SMTP, PagerDuty alert, etc.). HumanApprover dispatches to its
// configured credential's notifier — adding a new channel =
// implementing this on a new credential plugin, no main-package
// changes.
type HITLNotifier interface {
	NotifyHITL(ctx context.Context, req ApproveRequest, target HITLTarget) error
}

// HITLTarget is the per-approver config the notifier needs:
// where to send the prompt, whether to render interactive buttons,
// and the pending entry's id (for action_id payload encoding).
type HITLTarget struct {
	CredentialName string // bare name — for SecretStore.Get
	Channel        string // routing target (#chan / chat_id / email)
	Interactive    bool   // approve/deny buttons vs. dashboard-only
	PendingID      string // pool's pending entry id
	DashboardURL   string // for fallback dashboard link in non-interactive mode
	ThreadTS       string // if set, post as a reply in this Slack thread
}

// ApproverRuntime evaluates one stage of an approve = [...] chain.
// Built-in approvers (dashboard, human, llm) implement it; out-of-tree
// plugins ship their own approver type and runtime via the same
// interface. Return Verdict + reason or surface a timeout.
//
// Implementations live on the approver plugin's decoded body so the
// dispatcher can type-assert and invoke per-approver logic without
// new wiring per type.
type ApproverRuntime interface {
	Approve(ctx context.Context, req ApproveRequest) (ApproveVerdict, error)
}

// ApproveRequest is the bundle handed to ApproverRuntime.Approve.
// Plugins read whatever they need (a Slack-targeted human approver
// reads only the summary; an LLM approver reads the full body).
type ApproveRequest struct {
	Stage    config.ApproveStage
	Endpoint *config.CompiledEndpoint
	Rule     *config.CompiledRule
	Request  *match.Request
	// ApproverName is the bare name from the stage — also the key the
	// approver should use against Pool / Secrets when it needs to
	// disambiguate per-approver state.
	ApproverName string
	// Profile of the originating peer; SecretStore lookup key for
	// per-profile credentials.
	Profile string
	// Method / Host / Path / UA / BodySample carry the request shape
	// for HITL prompts. Endpoint plugins fill these so approvers
	// don't have to know the family-specific Request internals.
	Method     string
	Host       string
	Path       string
	UA         string
	BodySample string
	Reason     string
	// ThreadTS, when set, asks HITL notifiers to post the approval
	// prompt as a reply in this Slack thread rather than top-level.
	// Populated from the X-HITL-Thread-TS request header.
	ThreadTS string

	// Pool exposes the gateway's shared pending-approval list — the
	// dashboard / Slack approvers use it to publish a pending entry
	// and block until a decision arrives. Synchronous approvers
	// (LLM) leave it nil-handled.
	Pool HITLPool
	// Secrets fetches the bot token / API key the approver needs to
	// post a notification or call an LLM judge.
	Secrets SecretStore
	// DashboardURL is the operator-facing dashboard origin used for
	// deep links in Slack messages and similar notifications.
	DashboardURL string

	// Policy gives approvers access to the full compiled policy —
	// HumanApprover uses it to look up its referenced credential
	// entity and dispatch via HITLNotifier.
	Policy *config.CompiledPolicy
}

// ApproveVerdict is what an approver returns. "" Decision means the
// approver couldn't decide (timeout / error) — the caller falls back
// to the configured fail mode.
type ApproveVerdict struct {
	Decision string // "allow" | "deny" | ""
	Reason   string
	By       string // who decided ("dashboard:<user>" / "slack:#chan" / "llm:<model>")
}

// HITLPool is the shared pending-approval surface the dashboard
// presents to operators. Approver runtimes that need human input
// (dashboard, Slack human-approver, etc.) call Add to publish an
// entry and block on the returned channel until the dashboard's
// PUT /api/hitl/decide signals back.
//
// The pool implementation lives in the gateway main package; runtime
// only declares the contract so approver plugins can satisfy
// ApproverRuntime without depending on main.
type HITLPool interface {
	// Add publishes a pending entry. Returns the assigned id (used
	// by Decide) and a channel that fires exactly once when the
	// pool gets a verdict. Caller must select on ctx.Done() too;
	// if ctx fires first, call Discard(id) to clean up.
	Add(p HITLPending) (id string, decision <-chan HITLDecision)
	// Discard drops a pending entry without a decision. Use when
	// the caller's context expires before the channel fires.
	Discard(id string)
	// Decide resolves a pending entry — used by webhook handlers
	// (Slack interactive callback, future Discord etc.) to forward
	// a side-channel verdict into the same pool the dashboard's
	// /api/hitl/decide writes to. Returns false when the id is
	// unknown (already resolved or expired).
	Decide(id string, d HITLDecision) bool
}

// HITLPending mirrors the dashboard's pending-approval shape. Stays
// here (vs main package) so approver plugins can construct it. JSON
// tags match the dashboard's existing field names — that endpoint is
// public API to the in-tree React UI.
type HITLPending struct {
	ID      string `json:"id"`
	AgentIP string `json:"agent_ip"`
	Host    string `json:"host"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	// Endpoint is the operator-readable identifier for what's being
	// called. HITLEndpointLabel-derived: hostname for HTTPS, resource
	// name for SQL / k8s where Host is a virtual IP.
	Endpoint string `json:"endpoint,omitempty"`
	// Family is the endpoint family ("https" | "sql" | "k8s") so the
	// dashboard can pick a matching label for Path ("Query" /
	// "Resource" / "Path"). Empty when no endpoint metadata is set.
	Family     string    `json:"family,omitempty"`
	UA         string    `json:"ua,omitempty"`
	BodySample string    `json:"body_sample,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Approvers  []string  `json:"approvers,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// HITLDecision is what the pool delivers when an operator approves
// or denies a pending entry.
type HITLDecision struct {
	Allow  bool
	Reason string
	By     string
}

// ErrUnsupported is returned by a plugin's runtime hook when the
// requested operation isn't implemented for that plugin yet (e.g.
// clickhouse_native endpoints have schema only). The dispatcher
// translates this into a clear "endpoint runtime not implemented"
// log entry and a 503 to the agent.
var ErrUnsupported = errors.New("plugin runtime not implemented")

// PlaceholderDetector is the optional contract an endpoint plugin's
// runtime implements so the multi-credential dispatch logic can ask
// it: "given this incoming request and these candidate placeholders,
// which one (if any) did the agent send?"
//
// The returned string must be one of `candidates` exactly, or "" if
// no placeholder matched (the caller then falls back to the
// no-placeholder credential entry, when one exists).
//
// Why an endpoint-plugin method rather than a callback handed to
// ResolveCredential: each protocol family hides placeholders in a
// different slot. HTTPS scans the Authorization header. Postgres
// reads the StartupMessage password. Putting the extraction logic on
// the endpoint plugin keeps the dispatcher protocol-agnostic.
//
// Endpoints with only singular `credential = X` bindings don't need
// to implement this — ResolveCredential short-circuits before
// calling it.
type PlaceholderDetector interface {
	DetectPlaceholder(req *Request, candidates []string) string
}

// Request is re-exported here so callers don't have to import
// config/match for the placeholder-detector signature.
type Request = match.Request
