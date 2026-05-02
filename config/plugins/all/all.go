// Package all blank-imports every built-in plugin so a single import
// from main / tests pulls the entire registry into the binary. Mirrors
// the Terraform provider blank-import pattern and lib/pq drivers.
package all

import (
	_ "github.com/denoland/clawpatrol-go/config/plugins/approvers"
	_ "github.com/denoland/clawpatrol-go/config/plugins/credentials"
	_ "github.com/denoland/clawpatrol-go/config/plugins/endpoints"
	_ "github.com/denoland/clawpatrol-go/config/plugins/rules"
)
