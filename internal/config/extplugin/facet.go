package extplugin

import (
	"fmt"
	"regexp"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"
	"github.com/hashicorp/hcl/v2"
)

// validCELIdent matches the CEL identifier production: ASCII letter
// or underscore, followed by letters / digits / underscores. Facet
// names and field names appear directly in rule conditions
// (`<facet>.<field>`), so anything outside this set means rules
// can't be written against the facet at all.
var validCELIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// pluginFacet is the synthetic facet.Runtime the gateway registers
// for each FacetDecl a plugin manifest carries. Data flows through
// the EvaluateAction stream message, not through PrepareRequest /
// Report — so those hooks are no-ops; the dashboard / rule loader
// only ever consult Name / EndpointFamilies / ReportFields /
// NewMatcher on this facet.
type pluginFacet struct {
	// name is the facet identifier — taken verbatim from the
	// plugin's FacetDecl.Name. The same string is used as the
	// facet registry key, the CEL variable in rule conditions
	// (`name.field`), and the value endpoint plugins set as
	// Family to bind to this facet.
	name         string
	reportFields []facet.ReportFieldSpec
	// kindByField is the per-field kind, kept so the gateway
	// adapter can identify FACET_STREAM fields (which need lazy
	// pulling) and zero-fill optional missing fields.
	kindByField map[string]pb.FacetKind
	// optionalFields is the set of field names plugin authors
	// declared optional. The adapter pre-fills missing entries
	// with the kind-zero value before CEL evaluation.
	optionalFields map[string]bool
	// streamFields lists the FACET_STREAM field names. Passed to
	// the CEL compiler as truncatablePaths so the dispatcher's
	// fail-closed-on-truncation contract (req.Truncated marks the
	// stream paths CEL-unknown) applies to plugin facets.
	streamFields []string
}

func (p *pluginFacet) Name() string                          { return p.name }
func (p *pluginFacet) EndpointFamilies() []string            { return []string{p.name} }
func (p *pluginFacet) Transport() string                     { return "" }
func (p *pluginFacet) HITLQueryLabel() string                { return "Action" }
func (p *pluginFacet) HostIsResource() bool                  { return false }
func (p *pluginFacet) ReportFields() []facet.ReportFieldSpec { return p.reportFields }
func (p *pluginFacet) PrepareRequest(*match.Request)         {}
func (p *pluginFacet) Report(*match.Request) map[string]any  { return nil }

func (p *pluginFacet) NewMatcher(condition string) (match.Matcher, error) {
	return newPluginFacetMatcher(p.name, condition, p.streamFields)
}

// registerFacet synthesizes a pluginFacet from a FacetDecl and
// installs it under the bare name from the decl. Returns a
// diagnostic when the name collides with another already-registered
// facet (built-in like "http", or another plugin's facet) so the
// operator sees a clean error from `clawpatrol validate` instead of
// a process panic from facet.Register.
func registerFacet(pluginName string, decl *pb.FacetDecl) hcl.Diagnostics {
	var diags hcl.Diagnostics
	if !validCELIdent.MatchString(decl.Name) {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Plugin %q facet %q: name is not a valid CEL identifier", pluginName, decl.Name),
			Detail:   "Facet names appear directly in rule conditions (`<facet>.<field>`); the name must match [A-Za-z_][A-Za-z0-9_]*.",
		})
	}
	for _, f := range decl.Fields {
		if f.Name == "" {
			continue // already reported by validateManifestShape
		}
		if !validCELIdent.MatchString(f.Name) {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Plugin %q facet %q field %q: name is not a valid CEL identifier", pluginName, decl.Name, f.Name),
				Detail:   "Facet field names appear directly in rule conditions; must match [A-Za-z_][A-Za-z0-9_]*.",
			})
		}
	}
	if diags.HasErrors() {
		return diags
	}
	if existing := facet.Lookup(decl.Name); existing != nil {
		owner := "built-in"
		if _, ok := existing.(*pluginFacet); ok {
			owner = "another plugin"
		}
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Plugin %q facet %q collides with existing %s facet", pluginName, decl.Name, owner),
			Detail:   "Pick a different facet name in the plugin's manifest, or remove the duplicate registration.",
		}}
	}
	kindByField := make(map[string]pb.FacetKind, len(decl.Fields))
	optional := make(map[string]bool)
	var streams []string
	for _, f := range decl.Fields {
		kindByField[f.Name] = f.Kind
		if f.Optional {
			optional[f.Name] = true
		}
		if f.Kind == pb.FacetKind_FACET_STREAM {
			streams = append(streams, f.Name)
		}
	}
	pf := &pluginFacet{
		name:           decl.Name,
		reportFields:   protoFacetFieldsToSpec(decl.Fields),
		kindByField:    kindByField,
		optionalFields: optional,
		streamFields:   streams,
	}
	facet.Register(pf)
	return nil
}

func protoFacetFieldsToSpec(in []*pb.FacetFieldDecl) []facet.ReportFieldSpec {
	out := make([]facet.ReportFieldSpec, 0, len(in))
	for _, f := range in {
		out = append(out, facet.ReportFieldSpec{
			Name:        f.Name,
			Kind:        pluginFacetKind(f.Kind),
			Label:       f.Label,
			Description: f.Description,
			Title:       f.Title,
			DetailOnly:  f.DetailOnly,
		})
	}
	return out
}

func pluginFacetKind(k pb.FacetKind) facet.ReportValueKind {
	switch k {
	case pb.FacetKind_FACET_STRING_LIST:
		return facet.ReportStringList
	case pb.FacetKind_FACET_STRING_MAP:
		return facet.ReportStringMap
	case pb.FacetKind_FACET_INT:
		return facet.ReportInt
	default:
		return facet.ReportString
	}
}
