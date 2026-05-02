package runtime

import (
	"fmt"

	"github.com/denoland/clawpatrol-go/config"
)

// init installs a plugin checker on the config registry that
// validates Plugin.Runtime, when non-nil, satisfies an interface this
// package recognizes for the plugin's Kind. Catches signature drift
// and miswired Runtime fields at init time instead of at first request.
//
// Plugins with Runtime == nil are always allowed — that's the
// schema-only case (e.g. clickhouse_native endpoints, telegram
// credentials with no injection runtime yet).
func init() {
	config.AddPluginChecker(checkRuntime)
}

func checkRuntime(p *config.Plugin) []string {
	if p.Runtime == nil {
		return nil
	}
	switch p.Kind {
	case config.KindCredential:
		_, http := p.Runtime.(HTTPCredentialRuntime)
		_, pg := p.Runtime.(PostgresCredentialRuntime)
		if !http && !pg {
			return []string{fmt.Sprintf("Runtime %T satisfies neither HTTPCredentialRuntime nor PostgresCredentialRuntime", p.Runtime)}
		}
	case config.KindEndpoint:
		// PlaceholderDetector is the only endpoint runtime contract
		// defined today (request-time HandleHTTP / HandleConn land
		// in a follow-up commit). Endpoint plugins may set Runtime
		// to a value that doesn't implement PlaceholderDetector iff
		// they have only singular credential bindings — no enforcement
		// here yet because the plugin's Validate already rejects
		// inconsistent shapes.
	case config.KindApprover:
		if _, ok := p.Runtime.(ApproverRuntime); !ok {
			return []string{fmt.Sprintf("Runtime %T does not satisfy ApproverRuntime", p.Runtime)}
		}
	}
	return nil
}
