package extplugin

import (
	"context"
	"fmt"

	"github.com/denoland/clawpatrol/config"
	pb "github.com/denoland/clawpatrol/config/extplugin/proto"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hcldec"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// RegisterManifest converts every type in resp into a virtual
// *config.Plugin and installs it in the global registry. The
// (Kind, Type) names are namespaced as "<plugin>.<type>" so two
// plugins can't collide on, say, "https".
//
// Returns hcl.Diagnostics for any per-type registration failure;
// the caller should attach the source range of the `plugin` block.
func RegisterManifest(client *Client, resp *pb.ManifestResponse) hcl.Diagnostics {
	var diags hcl.Diagnostics
	// Facets register first so endpoints below can bind to them by
	// name. Endpoint Family values are taken verbatim — a plugin
	// that wants to use a built-in facet (e.g. "http") sets
	// Family="http"; one that ships its own facet sets
	// Family="<own-name>". Collisions with built-in facets or
	// across plugins fail loudly at registration; that's the
	// plugin author's concern, not the framework's.
	for _, f := range resp.Facets {
		registerFacet(f)
	}
	for _, c := range resp.Credentials {
		if d := registerCredential(client, resp.Name, c); d != nil {
			diags = append(diags, d...)
		}
	}
	for _, t := range resp.Tunnels {
		if d := registerTunnel(client, resp.Name, t); d != nil {
			diags = append(diags, d...)
		}
	}
	for _, e := range resp.Endpoints {
		if d := registerEndpoint(client, resp.Name, e); d != nil {
			diags = append(diags, d...)
		}
	}
	return diags
}

// =====================================================================
// Credential registration
// =====================================================================

func registerCredential(client *Client, pluginName string, decl *pb.CredentialDecl) hcl.Diagnostics {
	typeName := pluginName + "." + decl.TypeName
	spec, err := schemaToSpec(decl.Schema)
	if err != nil {
		return fail("plugin %q credential %q: %v", pluginName, decl.TypeName, err)
	}

	plug := &config.Plugin{
		Kind: config.KindCredential,
		Type: typeName,
		New:  func() any { return &dynamicCredentialBody{} },
		DecodeBody: func(body hcl.Body, ctx *hcl.EvalContext, target any) hcl.Diagnostics {
			b := target.(*dynamicCredentialBody)
			val, d := hcldec.Decode(body, spec, ctx)
			if d.HasErrors() {
				return d
			}
			j, err := ctyjson.Marshal(val, val.Type())
			if err != nil {
				return hcl.Diagnostics{{Severity: hcl.DiagError, Summary: "marshal credential body", Detail: err.Error()}}
			}
			b.canonicalJSON = j
			return d
		},
		Build: func(decoded any, name string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
			b := decoded.(*dynamicCredentialBody)
			resp, err := client.PluginRPC().Build(context.Background(), &pb.BuildRequest{
				Kind: "credential", TypeName: decl.TypeName, InstanceName: name, ConfigJson: b.canonicalJSON,
			})
			if err != nil {
				return nil, fail("plugin %q credential %q: build: %v", pluginName, name, err)
			}
			if d := protoDiagsToHCL(resp.Diagnostics); d.HasErrors() {
				return nil, d
			}
			if len(resp.CanonicalJson) > 0 {
				b.canonicalJSON = resp.CanonicalJson
			}
			return b, nil
		},
		Emit: func(_ any, _ string, _ *hclwrite.Body) {},
	}
	if config.Lookup(plug.Kind, plug.Type) == nil {
		config.Register(plug)
	}
	return nil
}

// =====================================================================
// Tunnel registration
// =====================================================================

func registerTunnel(client *Client, pluginName string, decl *pb.TunnelDecl) hcl.Diagnostics {
	typeName := pluginName + "." + decl.TypeName
	spec, err := schemaToSpec(decl.Schema)
	if err != nil {
		return fail("plugin %q tunnel %q: %v", pluginName, decl.TypeName, err)
	}
	adapter := &tunnelAdapter{client: client, typeName: decl.TypeName}

	plug := &config.Plugin{
		Kind: config.KindTunnel,
		Type: typeName,
		New:  func() any { return &dynamicTunnelBody{adapter: adapter} },
		DecodeBody: func(body hcl.Body, ctx *hcl.EvalContext, target any) hcl.Diagnostics {
			b := target.(*dynamicTunnelBody)
			val, d := hcldec.Decode(body, spec, ctx)
			if d.HasErrors() {
				return d
			}
			j, err := ctyjson.Marshal(val, val.Type())
			if err != nil {
				return hcl.Diagnostics{{Severity: hcl.DiagError, Summary: "marshal tunnel body", Detail: err.Error()}}
			}
			b.canonicalJSON = j
			return d
		},
		Build: func(decoded any, name string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
			b := decoded.(*dynamicTunnelBody)
			b.instanceName = name
			resp, err := client.PluginRPC().Build(context.Background(), &pb.BuildRequest{
				Kind: "tunnel", TypeName: decl.TypeName, InstanceName: name, ConfigJson: b.canonicalJSON,
			})
			if err != nil {
				return nil, fail("plugin %q tunnel %q: build: %v", pluginName, name, err)
			}
			if d := protoDiagsToHCL(resp.Diagnostics); d.HasErrors() {
				return nil, d
			}
			if len(resp.CanonicalJson) > 0 {
				b.canonicalJSON = resp.CanonicalJson
			}
			tunnelBodies.mu.Lock()
			tunnelBodies.m[name] = b
			tunnelBodies.mu.Unlock()
			return b, nil
		},
		Runtime: adapter,
		Emit:    func(_ any, _ string, _ *hclwrite.Body) {},
	}
	if config.Lookup(plug.Kind, plug.Type) == nil {
		config.Register(plug)
	}
	return nil
}

// =====================================================================
// Endpoint registration
// =====================================================================

// Reserved attribute names the framework injects on every external
// endpoint's body, regardless of what the plugin declared.
const (
	endpointAttrHosts      = "hosts"
	endpointAttrCredential = "credential"
)

func registerEndpoint(client *Client, pluginName string, decl *pb.EndpointDecl) hcl.Diagnostics {
	typeName := pluginName + "." + decl.TypeName
	spec, pluginAttrNames, err := endpointSpec(decl.Schema)
	if err != nil {
		return fail("plugin %q endpoint %q: %v", pluginName, decl.TypeName, err)
	}

	adapter := &endpointAdapter{
		client:      client,
		typeName:    decl.TypeName,
		tlsMode:     decl.TlsMode,
		requiresVIP: decl.RequiresVip,
	}

	plug := &config.Plugin{
		Kind:   config.KindEndpoint,
		Type:   typeName,
		Family: decl.Family,
		New: func() any {
			return &dynamicEndpointBody{
				adapter:      adapter,
				tlsTerminate: decl.TlsMode == pb.TLSMode_TLS_TERMINATE,
				wantsVIP:     decl.RequiresVip,
			}
		},
		DecodeBody: func(body hcl.Body, ctx *hcl.EvalContext, target any) hcl.Diagnostics {
			b := target.(*dynamicEndpointBody)
			val, d := hcldec.Decode(body, spec, ctx)
			if d.HasErrors() {
				return d
			}
			// Pull framework-injected fields off the value.
			obj := val.AsValueMap()
			if hostsV, ok := obj[endpointAttrHosts]; ok && !hostsV.IsNull() {
				for it := hostsV.ElementIterator(); it.Next(); {
					_, h := it.Element()
					b.hosts = append(b.hosts, h.AsString())
				}
			}
			if credV, ok := obj[endpointAttrCredential]; ok && !credV.IsNull() {
				b.credentialName = credV.AsString()
			}
			// Plugin-only payload — drop the framework attrs.
			pluginObj := make(map[string]cty.Value, len(pluginAttrNames))
			for _, name := range pluginAttrNames {
				pluginObj[name] = obj[name]
			}
			if len(pluginObj) > 0 {
				pv := cty.ObjectVal(pluginObj)
				j, err := ctyjson.Marshal(pv, pv.Type())
				if err != nil {
					return hcl.Diagnostics{{Severity: hcl.DiagError, Summary: "marshal endpoint body", Detail: err.Error()}}
				}
				b.canonicalJSON = j
			}
			return d
		},
		Build: func(decoded any, name string, ctx *config.BuildCtx) (any, hcl.Diagnostics) {
			b := decoded.(*dynamicEndpointBody)
			b.instanceName = name
			// Validate the credential ref (if any) against the symbol
			// table now that we have it.
			var diags hcl.Diagnostics
			if b.credentialName != "" {
				if sym := ctx.Symbols.Get(config.KindCredential, b.credentialName); sym == nil {
					diags = append(diags, &hcl.Diagnostic{
						Severity: hcl.DiagError,
						Summary:  fmt.Sprintf("Unknown credential %q", b.credentialName),
						Detail:   fmt.Sprintf("Endpoint %q references undeclared credential %q.", name, b.credentialName),
						Subject:  &ctx.Block.DefRange,
					})
				}
			}
			if diags.HasErrors() {
				return nil, diags
			}
			resp, err := client.PluginRPC().Build(context.Background(), &pb.BuildRequest{
				Kind: "endpoint", TypeName: decl.TypeName, InstanceName: name, ConfigJson: b.canonicalJSON,
			})
			if err != nil {
				return nil, fail("plugin %q endpoint %q: build: %v", pluginName, name, err)
			}
			if d := protoDiagsToHCL(resp.Diagnostics); d.HasErrors() {
				return nil, d
			}
			if len(resp.CanonicalJson) > 0 {
				b.canonicalJSON = resp.CanonicalJson
			}
			return b, nil
		},
		Runtime: adapter,
		Emit:    func(_ any, _ string, _ *hclwrite.Body) {},
	}
	if config.Lookup(plug.Kind, plug.Type) == nil {
		config.Register(plug)
	}
	return nil
}

// EndpointCredentials lets the compile pass pick up the resolved
// credential binding without baking knowledge of dynamic plugin
// bodies into config/compile.go.
func (b *dynamicEndpointBody) EndpointCredentials() []config.CredBinding {
	if b.credentialName == "" {
		return nil
	}
	return []config.CredBinding{{Credential: b.credentialName}}
}

// credentialName is the resolved credential bare-name, populated by
// the synthesized DecodeBody.
type endpointDecodeExtras struct{ credentialName string }

func init() {
	// Compile-time sanity: dynamicEndpointBody satisfies the
	// reflective interface compile.go expects.
	var _ interface {
		EndpointHosts() []string
		EndpointCredentials() []config.CredBinding
	} = (*dynamicEndpointBody)(nil)
}

// =====================================================================
// Helpers
// =====================================================================

// schemaToSpec converts a manifest Schema into an hcldec.ObjectSpec.
func schemaToSpec(s *pb.Schema) (hcldec.Spec, error) {
	fields := hcldec.ObjectSpec{}
	if s == nil {
		return fields, nil
	}
	for _, f := range s.Fields {
		ty, err := ctyTypeFromString(f.TypeString)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", f.Name, err)
		}
		fields[f.Name] = &hcldec.AttrSpec{
			Name:     f.Name,
			Type:     ty,
			Required: f.Required,
		}
	}
	return fields, nil
}

// endpointSpec returns the body spec for an external endpoint type:
// the plugin-declared fields plus the always-injected `hosts` and
// `credential` attributes. The second return is the list of
// plugin-declared attribute names so the synthesized DecodeBody can
// strip the framework-injected ones before forwarding to Build.
func endpointSpec(s *pb.Schema) (hcldec.Spec, []string, error) {
	out := hcldec.ObjectSpec{
		endpointAttrHosts:      &hcldec.AttrSpec{Name: endpointAttrHosts, Type: cty.List(cty.String), Required: true},
		endpointAttrCredential: &hcldec.AttrSpec{Name: endpointAttrCredential, Type: cty.String, Required: false},
	}
	var names []string
	if s != nil {
		for _, f := range s.Fields {
			if f.Name == endpointAttrHosts || f.Name == endpointAttrCredential {
				return nil, nil, fmt.Errorf("plugin declared reserved attribute %q", f.Name)
			}
			ty, err := ctyTypeFromString(f.TypeString)
			if err != nil {
				return nil, nil, fmt.Errorf("field %q: %w", f.Name, err)
			}
			out[f.Name] = &hcldec.AttrSpec{Name: f.Name, Type: ty, Required: f.Required}
			names = append(names, f.Name)
		}
	}
	return out, names, nil
}

// ctyTypeFromString parses a small subset of cty type strings the v1
// plugin protocol supports. The full cty type-expression grammar is
// overkill for the schemas we accept; we only need the primitives
// plus list(...) of primitives.
func ctyTypeFromString(s string) (cty.Type, error) {
	switch s {
	case "string":
		return cty.String, nil
	case "bool":
		return cty.Bool, nil
	case "number":
		return cty.Number, nil
	case "list(string)":
		return cty.List(cty.String), nil
	case "list(number)":
		return cty.List(cty.Number), nil
	case "list(bool)":
		return cty.List(cty.Bool), nil
	case "":
		return cty.String, nil
	}
	return cty.NilType, fmt.Errorf("unsupported type string %q (allowed: string, bool, number, list(string|bool|number))", s)
}

func protoDiagsToHCL(in []*pb.Diagnostic) hcl.Diagnostics {
	if len(in) == 0 {
		return nil
	}
	out := make(hcl.Diagnostics, 0, len(in))
	for _, d := range in {
		sev := hcl.DiagError
		if d.Severity == pb.Diagnostic_WARNING {
			sev = hcl.DiagWarning
		}
		out = append(out, &hcl.Diagnostic{
			Severity: sev,
			Summary:  d.Summary,
			Detail:   d.Detail,
		})
	}
	return out
}

func fail(format string, args ...any) hcl.Diagnostics {
	return hcl.Diagnostics{{Severity: hcl.DiagError, Summary: fmt.Sprintf(format, args...)}}
}
