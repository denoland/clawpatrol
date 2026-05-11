// Package all blank-imports every built-in plugin so a single import
// from main / tests pulls the entire registry into the binary. Mirrors
// the Terraform provider blank-import pattern and lib/pq drivers.
package all

import (
	_ "github.com/denoland/clawpatrol/config/plugins/approvers" // register built-in plugin
	_ "github.com/denoland/clawpatrol/config/plugins/credentials"
	_ "github.com/denoland/clawpatrol/config/plugins/endpoints"
	// Facet packages register both their facet runtime and the
	// corresponding `<facet>_rule` KindRule plugin. The legacy
	// rules package is now a library — it no longer has its own
	// init() — so the rule registrations come from these imports.
	_ "github.com/denoland/clawpatrol/config/plugins/facets/https"
	_ "github.com/denoland/clawpatrol/config/plugins/facets/k8s"
	_ "github.com/denoland/clawpatrol/config/plugins/facets/sql"
	_ "github.com/denoland/clawpatrol/config/plugins/tunnels"
)
