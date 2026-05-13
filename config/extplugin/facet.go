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
	// name is the namespaced facet name ("<plugin>.<short>") —
	// what facet.Register uses as the registry key and what
	// endpoints set as their Family.
	name string
	// shortName is the plugin-author-supplied identifier used as
	// the CEL variable in rule conditions. Built-in facets get the
	// same identifier in both places (e.g. "k8s"); plugin facets
	// keep them separate so two plugins can each export "smtp"
	// without colliding while rules stay readable.
	shortName    string
	reportFields []facet.ReportFieldSpec
	// kindByField is the per-field kind, kept so the gateway
	// adapter can identify FACET_STREAM fields (which need lazy
	// pulling) and zero-fill optional missing fields.
	kindByField map[string]pb.FacetKind
	// optionalFields is the set of field names plugin authors
	// declared optional. The adapter pre-fills missing entries
	// with the kind-zero value before CEL evaluation.
	optionalFields map[string]bool
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
	return newPluginFacetMatcher(p.shortName, condition)
}

// registerFacet synthesizes a pluginFacet from a FacetDecl and
// installs it under the namespaced name "<plugin>.<facet>". Idempotent
// (skips re-registration on hot-reload).
func registerFacet(pluginName string, decl *pb.FacetDecl) *pluginFacet {
	name := pluginName + "." + decl.Name
	if existing := facet.Lookup(name); existing != nil {
		if pf, ok := existing.(*pluginFacet); ok {
			return pf
		}
		return nil
	}
	kindByField := make(map[string]pb.FacetKind, len(decl.Fields))
	optional := make(map[string]bool)
	for _, f := range decl.Fields {
		kindByField[f.Name] = f.Kind
		if f.Optional {
			optional[f.Name] = true
		}
	}
	pf := &pluginFacet{
		name:           name,
		shortName:      decl.Name,
		reportFields:   protoFacetFieldsToSpec(decl.Fields),
		kindByField:    kindByField,
		optionalFields: optional,
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
