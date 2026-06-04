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

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/match"
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

// HTTPRequestSigner is the credential-plugin contract for HTTP auth
// shapes whose signature spans the *whole request* (method, URL,
// headers, body) and need parameters that live on the endpoint, not
// the credential. AWS SigV4 is the canonical example: the signature
// depends on the service + region declared on the endpoint, plus a
// hash of the request body. HTTPCredentialRuntime.InjectHTTP only
// gets the request, not the endpoint, so signing schemes that need
// endpoint context implement this instead.
//
// SignHTTPRequest may consume and replace req.Body (typically reading
// it in full to hash, then restoring with io.NopCloser); callers must
// not assume the body is preserved verbatim.
//
// The endpoint argument is the endpoint plugin's decoded Body (the
// same value as CompiledEndpoint.Body). The signer type-asserts it
// against an interface that exposes the parameters it needs (e.g.
// `AWSSigningParams() (service, region string)`).
type HTTPRequestSigner interface {
	SignHTTPRequest(ctx context.Context, req *http.Request, sec Secret, endpoint any) error
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

// EndpointTLSConfigurer is the optional hook an endpoint plugin
// implements when it carries upstream-TLS state that doesn't belong
// on a credential — most commonly a cluster-scoped CA pin. The
// kubernetes endpoint implements it to apply its ca_cert HCL field
// to cfg.RootCAs before the upstream dial: EKS apiservers present
// per-cluster CAs that no system trust store knows about, and the
// aws_credential plugin handles bearer auth, not root verification.
//
// Called by dialUpstream before any credential's ConfigureUpstreamTLS,
// so a credential can still override RootCAs / append Certificates
// when it has good reason to.
type EndpointTLSConfigurer interface {
	ConfigureUpstreamTLS(cfg *tls.Config) error
}

// EKSBearerMinter is the credential-plugin contract for minting a
// k8s-aws-v1.<…> bearer scoped to one (region, cluster) pair. The
// kubernetes_port_forward tunnel uses this to materialise a temp
// kubeconfig at Open time, so operators can drop the external
// awscli + kubeconfig + KUBECONFIG-in-systemd glue: HCL declares the
// cluster shape (server + ca_cert + cluster_name + region) and binds
// an aws_credential that satisfies this interface; the tunnel mints,
// writes, and cleans up the per-tunnel kubeconfig itself.
//
// The HTTPRequestSigner path (kubernetes endpoint, per-request HTTP
// auth) calls the same underlying STS presigner — both shapes route
// through one mint helper so signature semantics stay in sync.
type EKSBearerMinter interface {
	MintEKSBearer(ctx context.Context, sec Secret, region, cluster string) (string, error)
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
	// before dispatch. Informational — the host uses it for logging
	// and exposes it to external plugins; it is no longer keyed into
	// credential lookups.
	Profile string
	// PeerIP is the agent's source IP. Informational identifier of
	// the originating peer.
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
	// StateDir is the gateway's persistent state root (matches
	// cfg.StateDir). Kept on the handle for tunnel plugins
	// (Tailscale's tsnet state dir is derived from it). Endpoint
	// plugins should persist material through Blobs instead — see
	// ConnHandle.Blobs.
	StateDir string
	// Blobs is the gateway's plugin-blob store. Endpoint plugins
	// that need persistent bytes (SSH host keys, JWT signing keys)
	// read / write through it instead of touching the filesystem.
	// The host backs it with a sqlite table; tests pass a fake.
	Blobs BlobStore
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
	Action  string // "allow" | "deny" | "approved" | "denied" | "error"
	Reason  string
	Verb    string // SQL verb / k8s verb / etc.
	Summary string // human-readable one-liner for the event log
	Bytes   int64  // approximate request size for billing / quotas
	Facets  map[string]any
	// Rule is the matched CompiledRule.Name, "" when no rule fired.
	// The host's Emit closure copies it onto the dashboard Event so
	// the action-fixture exporter can pin a downloaded action to a
	// specific rule (site/doc/clawpatrol-test.md).
	Rule string
	// Approver* mirror ApproveVerdict — set for Action=="approved" /
	// "denied" so the dashboard can show which approver (and what
	// kind: human / llm / dashboard) produced the verdict.
	Approver     string
	ApproverType string
	ApproverBy   string
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

// HITLMessageUpdateSink records a channel-specific message reference
// (for example Slack channel/ts) after a notifier posts a prompt.
// Implementations must not store tokens or other secrets in ref.
type HITLMessageUpdateSink func(ctx context.Context, operationID, ref string) error

// HITLPendingMessageUpdateSink records a channel-specific message reference
// against a live synchronous pending HITL request. Implementations must not
// store tokens or other secrets in ref.
type HITLPendingMessageUpdateSink func(ctx context.Context, pendingID, ref string) error

// HITLMessageUpdater is optionally implemented by notifier credentials that
// can update an already-posted HITL prompt as the durable operation moves
// through async states.
type HITLMessageUpdater interface {
	UpdateHITLMessage(ctx context.Context, secrets SecretStore, update HITLMessageUpdate) error
}

// HITLHumanCredentialer is implemented by approvers that route human HITL
// prompts through a named credential notifier.
type HITLHumanCredentialer interface {
	HumanApproverCredential() string
}

// HITLMessageUpdate is the payload an approver receives when a HITL
// decision lands. Credential plugins (e.g. Slack) use it to edit the
// originating interactive message with the final state.
type HITLMessageUpdate struct {
	MessageRef     string
	OperationID    string
	State          HITLOperationState
	Method         string
	Host           string
	Path           string
	Profile        string
	UpstreamCalled bool
	LastError      string
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
	// OperationState / ApprovalEffect / UpstreamCalled / ApprovalMessage
	// mirror HITLPending's safety copy so channel notifiers can tell
	// operators whether an approval executes upstream immediately or only
	// authorizes a one-shot retry grant.
	OperationState  HITLOperationState
	ApprovalEffect  HITLApprovalEffect
	UpstreamCalled  bool
	ApprovalMessage string
	// Summary is an optional pre-computed classification. When non-nil,
	// notifiers render a richer card instead of the generic method/path display.
	Summary *HITLSummary
	// Message is an optional pre-expanded template string. When non-empty,
	// notifiers use it as the section text, overriding the default path
	// display and the Summary card.
	Message string
	// MessageUpdateSink records a notifier-specific, non-secret message ref
	// for async HITL operation status updates.
	MessageUpdateSink HITLMessageUpdateSink
	// PendingMessageUpdateSink records a notifier-specific, non-secret
	// message ref for synchronous pending HITL terminal updates.
	PendingMessageUpdateSink HITLPendingMessageUpdateSink
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
	// AgentIP is the WireGuard source IP of the originating peer.
	// Used as the HITLPending.AgentIP key and as a log identifier.
	AgentIP string
	// Profile is the tenant profile the originating peer is bound to
	// (e.g. "dev2"). Informational — approvers use it as a
	// human-readable label in slack cards / log lines / message
	// templates; it carries no credential-lookup meaning.
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
	// NotifyChannel, when set, overrides the static channel declared in
	// the human_approver HCL block. Populated from X-HITL-Channel header.
	// Lets agents route approvals into their own Slack session thread.
	NotifyChannel string
	// AsyncOperationID binds the prompt to a durable async operation.
	// If AsyncPendingOnSyncTimeout is true and ctx hits DeadlineExceeded,
	// human_approver leaves the prompt pending and returns async_pending.
	AsyncOperationID          string
	AsyncPendingOnSyncTimeout bool

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
	// MessageUpdateSink records channel message references for async HITL
	// operation updates after notifiers successfully post prompts.
	MessageUpdateSink HITLMessageUpdateSink
	// PendingMessageUpdateSink records channel message references for live
	// synchronous HITL prompts so terminal timeout/disconnect states can be
	// reflected back to the original operator-facing message.
	PendingMessageUpdateSink HITLPendingMessageUpdateSink
}

// ApproveDecisionAsyncPending is the ApproveVerdict.Decision value an
// approver returns when no synchronous verdict was reached and the
// operation is being recorded for async resolution.
const ApproveDecisionAsyncPending = "async_pending"

// ApproveVerdict is what an approver returns. "" Decision means the
// approver couldn't decide (timeout / error) — the caller falls back
// to the configured fail mode.
//
// ApproverName / ApproverType identify which approver entity produced
// the verdict. The dispatcher reads these to label the resulting
// dashboard event with the deciding approver's kind (human / llm /
// dashboard) and id (the HCL block name) — operators looking at a
// `denied` row see *why* without having to drill into the rule.
type ApproveVerdict struct {
	Decision     string // "allow" | "deny" | "async_pending" | ""
	Reason       string
	By           string // who decided ("dashboard:<user>" / "slack:#chan" / "llm:<model>")
	ApproverName string // HCL block name, e.g. "pg-staging-secret-columns-judge"
	ApproverType string // plugin type, e.g. "llm_approver" / "human_approver" / "dashboard"
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
	// when ctx fires first, prefer HITLPoolCanceler.Cancel so stale
	// prompts can explain why the upstream request was not sent.
	Add(p HITLPending) (id string, decision <-chan HITLDecision)
	// Discard drops a pending entry without recording terminal state.
	// Use only for compatibility or best-effort cleanup after resolve.
	Discard(id string)
	// Decide resolves a pending entry — used by webhook handlers
	// (Slack interactive callback, future Discord etc.) to forward
	// a side-channel verdict into the same pool the dashboard's
	// /api/hitl/decide writes to. Returns false when the id is
	// unknown (already resolved or expired).
	Decide(id string, d HITLDecision) bool
}

// HITLPoolDecider is implemented by pools that can explain why a
// decision was accepted or rejected. Callers should prefer this over
// Decide when rendering operator-facing stale-click messages.
type HITLPoolDecider interface {
	DecideWithResult(id string, d HITLDecision) HITLResolveResult
}

// HITLPoolCanceler is implemented by pools that preserve a short-lived
// terminal state when a synchronous HITL request ends without a human
// decision (timeout, client disconnect, gateway cancellation).
type HITLPoolCanceler interface {
	Cancel(id string, state HITLState, reason string) HITLResolveResult
}

// HITLPoolUpdater is implemented by pools that can update operator-facing
// safety-copy metadata for an existing pending prompt without resolving it.
type HITLPoolUpdater interface {
	Update(id string, mutate func(*HITLPending)) bool
}

// HITLPoolAsyncGrantResolver lets pools bind a pending human decision to a
// durable async operation. Implementations must not execute upstream here;
// approval only moves the operation to a retry-grant state.
type HITLPoolAsyncGrantResolver interface {
	ResolveAsyncHITLGrant(operationID string, d HITLDecision) HITLResolveResult
}

// HITLState names the lifecycle state of a human approval prompt.
type HITLState string

// HITL terminal states exposed to dashboard and Slack stale-click handlers.
const (
	HITLStatePending            HITLState = "pending"
	HITLStateApproved           HITLState = "approved"
	HITLStateDenied             HITLState = "denied"
	HITLStateTimedOut           HITLState = "timed_out"
	HITLStateClientDisconnected HITLState = "client_disconnected"
	HITLStateCanceled           HITLState = "canceled"
	HITLStateUnknown            HITLState = "unknown"
)

// HITLOperationState is the durable async-HITL operation state copied
// into human-facing pending prompts. It intentionally lives in runtime
// (instead of main) so dashboard and channel notifiers can share the same
// wire labels without importing the gateway package.
type HITLOperationState string

// HITLOperationState values: durable lifecycle states for async-HITL
// operations.
const (
	HITLOperationStateSyncWaiting             HITLOperationState = "sync_waiting"
	HITLOperationStatePendingApproval         HITLOperationState = "pending_approval"
	HITLOperationStateApprovedWaitingForRetry HITLOperationState = "approved_waiting_for_retry"
	HITLOperationStateDenied                  HITLOperationState = "denied"
	HITLOperationStateExpired                 HITLOperationState = "expired"
	HITLOperationStateExecutingUpstream       HITLOperationState = "executing_upstream"
	HITLOperationStateUpstreamSucceeded       HITLOperationState = "upstream_succeeded"
	HITLOperationStateUpstreamFailed          HITLOperationState = "upstream_failed"
	HITLOperationStateClientDisconnected      HITLOperationState = "client_disconnected"
)

// HITLApprovalEffect tells an operator what clicking approve does for
// the current state. This is separate from OperationState so the UI can
// render a stable affordance even while async operation wiring evolves.
type HITLApprovalEffect string

// HITLApprovalEffect values: what clicking approve will do given the
// current HITLOperationState.
const (
	HITLApprovalEffectExecuteUpstream  HITLApprovalEffect = "execute_upstream"
	HITLApprovalEffectCreateRetryGrant HITLApprovalEffect = "create_retry_grant"
)

// HITLResolveResult is returned by structured HITL resolution APIs.
// OK means this call transitioned an active pending request. State and
// Reason are still populated for stale/duplicate decisions so Slack and
// the dashboard can distinguish timed-out, disconnected, and already
// decided prompts instead of showing a generic expired message.
type HITLResolveResult struct {
	OK     bool      `json:"ok"`
	State  HITLState `json:"state"`
	Reason string    `json:"reason,omitempty"`
}

// HITLPending mirrors the dashboard's pending-approval shape. Stays
// here (vs main package) so approver plugins can construct it. JSON
// tags match the dashboard's existing field names — that endpoint is
// public API to the in-tree React UI.
type HITLPending struct {
	ID          string `json:"id"`
	OperationID string `json:"operation_id,omitempty"`
	AgentIP     string `json:"agent_ip"`
	Host        string `json:"host"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	// OperationState and ApprovalEffect are safety-boundary display
	// metadata. They let dashboard/Slack copy distinguish the initial
	// synchronous wait (approval forwards upstream immediately) from async
	// fallback (approval only grants one matching client retry).
	OperationState  HITLOperationState `json:"operation_state,omitempty"`
	ApprovalEffect  HITLApprovalEffect `json:"approval_effect,omitempty"`
	UpstreamCalled  bool               `json:"upstream_called"`
	ApprovalMessage string             `json:"approval_message,omitempty"`
	// Endpoint is the operator-readable identifier for what's being
	// called. HITLEndpointLabel-derived: hostname for HTTPS, resource
	// name for SQL / k8s where Host is a virtual IP.
	Endpoint string `json:"endpoint,omitempty"`
	// Family is the endpoint family ("http" | "sql" | "k8s") so the
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

// NormalizeHITLPendingApproval fills safety copy defaults for a pending
// HITL prompt. Existing synchronous human-approval prompts start in
// sync_waiting: approving while the original request is still held sends
// the request upstream immediately. Async grant code can override the
// state/effect/message when sync_wait_timeout has already returned 202.
func NormalizeHITLPendingApproval(p *HITLPending) {
	if p == nil {
		return
	}
	if p.OperationState == "" {
		p.OperationState = HITLOperationStateSyncWaiting
	}
	if p.ApprovalEffect == "" {
		p.ApprovalEffect = HITLApprovalEffectForOperationState(p.OperationState)
	}
	if p.ApprovalMessage == "" {
		p.ApprovalMessage = HITLApprovalMessage(p.OperationState, p.ApprovalEffect, p.UpstreamCalled)
	}
}

// HITLApprovalEffectForOperationState returns the effect that clicking
// approve will have given the supplied operation state.
func HITLApprovalEffectForOperationState(state HITLOperationState) HITLApprovalEffect {
	switch state {
	case HITLOperationStatePendingApproval:
		return HITLApprovalEffectCreateRetryGrant
	default:
		return HITLApprovalEffectExecuteUpstream
	}
}

// HITLApprovalMessage returns the operator-facing description of what
// approving the pending request will do, given the operation's current
// state, the precomputed approval effect, and whether the upstream
// call already started.
func HITLApprovalMessage(state HITLOperationState, effect HITLApprovalEffect, upstreamCalled bool) string {
	if upstreamCalled {
		switch state {
		case HITLOperationStateExecutingUpstream:
			return "The client retried the approved request.\nForwarding upstream now."
		case HITLOperationStateUpstreamSucceeded:
			return "Done. The approved request completed upstream."
		case HITLOperationStateUpstreamFailed:
			return "Approved and retried, but the forwarding attempt failed or did not complete successfully.\nThe upstream side effect status may be unknown."
		}
	}
	switch state {
	case HITLOperationStatePendingApproval:
		return "The original synchronous wait ended and Claw Patrol returned an async polling response to the client.\nUpstream has not been called.\nApprove will not send the request upstream now.\nApprove will allow the client to retry the same request once."
	case HITLOperationStateApprovedWaitingForRetry:
		return "Approved.\nWaiting for the client to retry the original request.\nUpstream has not been called yet."
	case HITLOperationStateDenied:
		return "Denied.\nUpstream was not called."
	case HITLOperationStateExpired:
		return "Approval expired.\nUpstream was not called."
	case HITLOperationStateClientDisconnected:
		return "The original client disconnected before approval completed.\nUpstream was not called.\nThis prompt is stale."
	}
	if effect == HITLApprovalEffectCreateRetryGrant {
		return "Upstream has not been called.\nApprove will not send the request upstream now.\nApprove will allow the client to retry the same request once."
	}
	return "Pending human approval.\nIf approved soon, Claw Patrol will send this request upstream immediately and return the real upstream response to the client."
}

// HITLDecision is what the pool delivers when an operator approves
// or denies a pending entry.
type HITLDecision struct {
	Allow  bool
	Reason string
	By     string
}

// HITLSummary is an optional pre-computed classification from a
// classifier LLM. When set on HITLTarget, notifiers build a richer
// approval card instead of the generic method/path display.
type HITLSummary struct {
	TicketID       string `json:"ticket_id"`
	Classification string `json:"classification"` // "Spam", "Legit", "Unclear", etc.
	Confidence     int    `json:"confidence"`     // 0–100; 0 = not provided
	Text           string `json:"summary"`
}

// HITLClassifier is the optional interface an approver plugin
// implements to generate a HITLSummary before the HITL notification
// is sent.
type HITLClassifier interface {
	Summarize(ctx context.Context, req ApproveRequest) (*HITLSummary, error)
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

// SQLParser is the optional contract a SQL-family endpoint plugin's
// runtime implements so a host that received a raw SQL string (rather
// than a live wire-protocol frame) can populate `match.Request.Meta`
// using the same parser the live dispatch path uses. The fixture
// loader behind `clawpatrol test` reads only `"statement": "..."`
// from each fixture and calls this to recover verb / tables /
// functions before running rule matching, so the format stays
// operator-friendly (site/doc/clawpatrol-test.md).
//
// Implementations return the per-family `*sqlfacet.Meta` value the
// SQL matcher expects on `match.Request.Meta`, plus a bool reporting
// whether the parser refused the input. When the bool is true the
// fixture loader sets `match.Request.Unparseable` so the unevaluable
// fail-close (parser facets become CEL unknowns) runs against the
// test rule set, mirroring live wire-frame dispatch.
// Endpoints whose runtime doesn't implement this aren't usable as
// SQL test fixtures.
type SQLParser interface {
	ParseStatement(sql string) (any, bool)
}

// Request is re-exported here so callers don't have to import
// config/match for the placeholder-detector signature.
type Request = match.Request
