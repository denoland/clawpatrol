package extplugin

import (
	pb "github.com/denoland/clawpatrol/config/extplugin/proto"
	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/match"
)

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
	// fail-closed-on-truncation gate (req.Truncated +
	// matcher.InspectsTruncatableFacet) applies to plugin facets.
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
// installs it under the bare name from the decl. Idempotent across
// hot-reloads (skips re-registration if a pluginFacet by that name
// is already present); duplicate names from different plugins or a
// collision with a built-in facet panic at startup so the operator
// notices.
func registerFacet(decl *pb.FacetDecl) *pluginFacet {
	if existing := facet.Lookup(decl.Name); existing != nil {
		if pf, ok := existing.(*pluginFacet); ok {
			return pf
		}
		return nil
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
	return pf
}

func protoFacetFieldsToSpec(in []*pb.FacetFieldDecl) []facet.ReportFieldSpec {
	out := make([]facet.ReportFieldSpec, 0, len(in))
	for _, f := range in {
		out = append(out, facet.ReportFieldSpec{
			Name:  f.Name,
			Kind:  pluginFacetKind(f.Kind),
			Label: f.Label,
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
