// Package all blank-imports every built-in plugin so a single import
// from main / tests pulls the entire registry into the binary. Mirrors
// the Terraform provider blank-import pattern and lib/pq drivers.
package all

//go:generate go run ../../../tools/docgen -o ../../../../site/doc/config-reference.md

import (
	_ "github.com/denoland/clawpatrol/internal/config/plugins/approvers" // register built-in plugin
	_ "github.com/denoland/clawpatrol/internal/config/plugins/credentials"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/endpoints"
	// Facet packages register their facet runtime only. The single
	// `rule` block plugin is registered by config/plugins/rules and
	// infers the family from each rule's endpoint set at validate
	// time.
	_ "github.com/denoland/clawpatrol/internal/config/plugins/facets/https"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/facets/k8s"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/facets/sql"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/rules"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/tunnels"
)
