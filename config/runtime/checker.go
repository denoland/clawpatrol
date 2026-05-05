package runtime

import (
	"fmt"

	"github.com/denoland/clawpatrol/config"
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

// extraCredChecks holds protocol-specific extensions to the credential
// runtime check. Plugin packages that introduce a new credential
// runtime interface (e.g. config/plugins/sshproto) call
// AcceptCredentialRuntime so their interface joins the accepted set
// without runtime needing to import the protocol-specific package.
var extraCredChecks []func(*config.Plugin) bool

// AcceptCredentialRuntime registers an additional credential
// runtime-interface check. checkRuntime accepts a credential plugin
// when ANY registered check (or built-in interface) matches its
// Runtime — out-of-tree credential families plug in here from their
// own init() rather than editing this file.
func AcceptCredentialRuntime(check func(*config.Plugin) bool) {
	extraCredChecks = append(extraCredChecks, check)
}

func checkRuntime(p *config.Plugin) []string {
	if p.Runtime == nil {
		return nil
	}
	switch p.Kind {
	case config.KindCredential:
		_, http := p.Runtime.(HTTPCredentialRuntime)
		_, pg := p.Runtime.(PostgresCredentialRuntime)
		_, pgAuth := p.Runtime.(PostgresAuthCredential)
		_, chAuth := p.Runtime.(ClickhouseAuthCredential)
		_, tlsR := p.Runtime.(TLSCredentialRuntime)
		if http || pg || pgAuth || chAuth || tlsR {
			return nil
		}
		for _, check := range extraCredChecks {
			if check(p) {
				return nil
			}
		}
		return []string{fmt.Sprintf("Runtime %T satisfies no credential runtime interface (HTTP / Postgres / Clickhouse / TLS or a registered protocol extension)", p.Runtime)}
	case config.KindEndpoint:
		// Endpoint plugins satisfy any combination of
		// PlaceholderDetector and ConnEndpointRuntime. Plugins with
		// only singular credential bindings need neither; the HTTPS
		// dispatcher walks them via the rule selectors directly.
		// Validate has already rejected schema inconsistencies.
	case config.KindApprover:
		if _, ok := p.Runtime.(ApproverRuntime); !ok {
			return []string{fmt.Sprintf("Runtime %T does not satisfy ApproverRuntime", p.Runtime)}
		}
	}
	return nil
}
