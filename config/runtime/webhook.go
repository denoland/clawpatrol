package runtime

// Webhook routes from credential plugins. A credential whose body
// implements WebhookProvider gets its routes mounted under
// /api/cred/<credName>/... by the dashboard mux at boot. Slack's
// interactive callback uses this; future Discord / Telegram /
// generic-webhook plugins plug in the same way without main needing
// a hardcoded path.
//
// Routes are public — they bypass the dashboard secret gate, since
// the originating service (Slack, Discord) authenticates via its own
// signature header and we have no other way to verify the channel.

import (
	"net/http"

	"github.com/denoland/clawpatrol/config"
)

// WebhookProvider is the optional interface a credential body
// implements when it wants to receive callbacks from the upstream
// service.
type WebhookProvider interface {
	WebhookRoutes() []WebhookRoute
}

// WebhookRoute is one mount under the credential's subtree. Path
// MUST start with "/" and gets joined under /api/cred/<credName>.
type WebhookRoute struct {
	Path    string
	Handler WebhookHandler
}

// WebhookHandler is the request handler — same as http.HandlerFunc
// plus a WebhookCtx with the runtime services the credential plugin
// needs (its own secret, the HITL pool, the policy snapshot).
type WebhookHandler func(ctx WebhookCtx, w http.ResponseWriter, r *http.Request)

// WebhookCtx is everything a credential's webhook handler may need
// from the gateway runtime. The credential's name is included so a
// shared handler factory can identify which credential it's serving.
type WebhookCtx struct {
	CredentialName string
	Secrets        SecretStore
	HITL           HITLPool
	Policy         *config.CompiledPolicy
	Profiles       []string
}
