package extplugin

import (
	"context"
	"fmt"
	"strings"

	"github.com/denoland/clawpatrol/internal/config"
	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
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
	// Up-front shape checks: empty names everywhere, reserved
	// characters in the plugin's own name, etc. Catches the
	// "manifest declares garbage" cases without waiting for an
	// HCL block to use the type.
	diags = append(diags, validateManifestShape(resp)...)
	if diags.HasErrors() {
		return diags
	}
	// Facets register first so endpoints below can bind to them by
	// name. Endpoint Family values are taken verbatim — a plugin
	// that wants to use a built-in facet (e.g. "http") sets
	// Family="http"; one that ships its own facet sets
	// Family="<own-name>". Collisions with built-in facets or
	// across plugins surface as diagnostics from registerFacet.
	for _, f := range resp.Facets {
		diags = append(diags, registerFacet(resp.Name, f)...)
	}
	for _, c := range resp.Credentials {
		diags = append(diags, registerCredential(client, resp.Name, c)...)
	}
	for _, t := range resp.Tunnels {
		diags = append(diags, registerTunnel(client, resp.Name, t)...)
	}
	for _, e := range resp.Endpoints {
		diags = append(diags, registerEndpoint(client, resp.Name, e)...)
	}
	return diags
}

// validateManifestShape rejects manifests with empty / reserved
// names before the per-type registers see them. The plugin
// subprocess is already running by the time this runs (Manager.Start
// already validated resp.Name is non-empty); this catches per-type
// shape problems.
func validateManifestShape(resp *pb.ManifestResponse) hcl.Diagnostics {
	var diags hcl.Diagnostics
	pluginName := resp.Name
	for i, f := range resp.Facets {
		if f.Name == "" {
			diags = append(diags, &hcl.Diagnostic{Severity: hcl.DiagError,
				Summary: fmt.Sprintf("Plugin %q manifest: facet #%d has empty name", pluginName, i)})
			continue
		}
		for j, fld := range f.Fields {
			if fld.Name == "" {
				diags = append(diags, &hcl.Diagnostic{Severity: hcl.DiagError,
					Summary: fmt.Sprintf("Plugin %q facet %q field #%d has empty name", pluginName, f.Name, j)})
			}
		}
	}
	for i, c := range resp.Credentials {
		if c.TypeName == "" {
			diags = append(diags, &hcl.Diagnostic{Severity: hcl.DiagError,
				Summary: fmt.Sprintf("Plugin %q manifest: credential #%d has empty type_name", pluginName, i)})
		}
	}
	for i, t := range resp.Tunnels {
		if t.TypeName == "" {
			diags = append(diags, &hcl.Diagnostic{Severity: hcl.DiagError,
				Summary: fmt.Sprintf("Plugin %q manifest: tunnel #%d has empty type_name", pluginName, i)})
		}
	}
	for i, e := range resp.Endpoints {
		if e.TypeName == "" {
			diags = append(diags, &hcl.Diagnostic{Severity: hcl.DiagError,
				Summary: fmt.Sprintf("Plugin %q manifest: endpoint #%d has empty type_name", pluginName, i)})
		}
		if e.Family == "" {
			diags = append(diags, &hcl.Diagnostic{Severity: hcl.DiagError,
				Summary: fmt.Sprintf("Plugin %q endpoint %q has empty family", pluginName, e.TypeName),
				Detail:  "Set Family to either a built-in facet (\"http\", \"sql\", \"k8s\") or to one of the plugin's own declared facet names so rules know which CEL env to use."})
		}
	}
	return diags
}

// =====================================================================
// Credential registration
// =====================================================================

func registerCredential(client *Client, pluginName string, decl *pb.CredentialDecl) hcl.Diagnostics {
	spec, err := schemaToSpec(decl.Schema)
	if err != nil {
		return fail("plugin %q credential %q: %v", pluginName, decl.TypeName, err)
	}
	adapter := &credentialAdapter{client: client, typeName: decl.TypeName}
	manifestMeta := credentialMetadataFromDecl(decl)

	plug := &config.Plugin{
		Kind:           config.KindCredential,
		Type:           decl.TypeName,
		Disambiguators: append([]string(nil), decl.Disambiguators...),
		New: func() any {
			return &dynamicCredentialBody{adapter: adapter, metadata: manifestMeta}
		},
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
			b.instanceName = name
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
			meta := manifestMeta
			if resp.CredentialMetadata != nil {
				if d := validateBuildDisambiguators(pluginName, decl.TypeName, decl.Disambiguators, resp.CredentialMetadata.Disambiguators); d.HasErrors() {
					return nil, d
				}
				if resp.CredentialMetadata.HttpInject && !decl.HttpInject && !decl.HttpTransform {
					return nil, fail("plugin %q credential %q: build metadata declared HTTP injection but manifest did not", pluginName, decl.TypeName)
				}
				if resp.CredentialMetadata.HttpTransform && !decl.HttpTransform {
					return nil, fail("plugin %q credential %q: build metadata declared HTTP transform but manifest did not", pluginName, decl.TypeName)
				}
				instanceMeta := credentialMetadataFromProto(resp.CredentialMetadata)
				if d := validateCredentialMetadataShape(pluginName, decl.TypeName, instanceMeta); d.HasErrors() {
					return nil, d
				}
				meta = mergeCredentialMetadata(manifestMeta, instanceMeta)
			}
			b.metadata = meta
			return wrapCredentialBody(b), nil
		},
		Emit: func(_ any, _ string, _ *hclwrite.Body) {},
	}
	if d := registerOrCollide(plug, pluginName, "credential"); d != nil {
		return d
	}
	return nil
}

func credentialMetadataFromDecl(decl *pb.CredentialDecl) credentialMetadata {
	if decl == nil {
		return credentialMetadata{}
	}
	return credentialMetadata{
		disambiguators: append([]string(nil), decl.Disambiguators...),
		httpInject:     decl.HttpInject || decl.HttpTransform,
		httpTransform:  decl.HttpTransform,
	}
}

func credentialMetadataFromProto(in *pb.CredentialMetadata) credentialMetadata {
	if in == nil {
		return credentialMetadata{}
	}
	out := credentialMetadata{
		disambiguators: append([]string(nil), in.Disambiguators...),
		httpInject:     in.HttpInject || in.HttpTransform,
		httpTransform:  in.HttpTransform,
	}
	for _, s := range in.SecretSlots {
		if s == nil {
			continue
		}
		out.secretSlots = append(out.secretSlots, config.SecretSlot{
			Name:        s.Name,
			Label:       s.Label,
			Multiline:   s.Multiline,
			Description: s.Description,
		})
	}
	for _, ev := range in.EnvVars {
		if ev == nil {
			continue
		}
		out.envVars = append(out.envVars, config.EnvVar{
			Name:        ev.Name,
			Value:       ev.Value,
			Description: ev.Description,
		})
	}
	if in.Oauth != nil {
		out.oauth = oauthIntegrationFromProto(in.Oauth)
	}
	return out
}

func oauthIntegrationFromProto(in *pb.OAuthIntegrationDecl) *config.OAuthIntegration {
	if in == nil {
		return nil
	}
	out := &config.OAuthIntegration{
		Type:   in.Type,
		Header: in.Header,
		Prefix: in.Prefix,
		Flow:   in.Flow,
	}
	if in.Oauth != nil {
		out.OAuth = config.OAuthConfig{
			ClientID:     in.Oauth.ClientId,
			ClientSecret: in.Oauth.ClientSecret,
			AuthURL:      in.Oauth.AuthUrl,
			TokenURL:     in.Oauth.TokenUrl,
			DeviceURL:    in.Oauth.DeviceUrl,
			RegisterURL:  in.Oauth.RegisterUrl,
			RedirectURI:  in.Oauth.RedirectUri,
			Scopes:       append([]string(nil), in.Oauth.Scopes...),
			RefreshToken: in.Oauth.RefreshToken,
		}
	}
	for _, g := range in.OptionalScopes {
		if g == nil {
			continue
		}
		group := config.OptionalScopeGroup{Title: g.Title}
		for _, s := range g.Scopes {
			if s == nil {
				continue
			}
			group.Scopes = append(group.Scopes, config.OptionalScope{ID: s.Id, Label: s.Label})
		}
		out.OptionalScopes = append(out.OptionalScopes, group)
	}
	return out
}

// mergeCredentialMetadata combines registration-time (base) and
// Build-time (instance) credential metadata. The per-instance
// surfaces — secret slots, env vars, OAuth — are wholesale REPLACED
// by the instance metadata, not appended: the manifest declaration
// cannot carry them, so whatever Build returned is the complete set
// for that instance.
func mergeCredentialMetadata(base, instance credentialMetadata) credentialMetadata {
	out := base
	out.secretSlots = instance.secretSlots
	out.envVars = instance.envVars
	// OAuth is intentionally instance-scoped Build metadata: region, scopes,
	// URLs, and flow can differ across two HCL blocks of the same type.
	out.oauth = instance.oauth
	// HTTP injection / transform are registration-time capabilities. Build
	// metadata can restate them but cannot enable them for a type whose
	// manifest did not declare them.
	out.httpInject = base.httpInject
	out.httpTransform = base.httpTransform
	return out
}

func validateCredentialMetadataShape(pluginName, typeName string, meta credentialMetadata) hcl.Diagnostics {
	seenSlots := map[string]bool{}
	unnamedSlots := 0
	for _, slot := range meta.secretSlots {
		name := strings.TrimSpace(slot.Name)
		if name == "" {
			unnamedSlots++
			if unnamedSlots > 1 {
				return fail("plugin %q credential %q: build metadata declared multiple unnamed secret slots", pluginName, typeName)
			}
			continue
		}
		if seenSlots[name] {
			return fail("plugin %q credential %q: build metadata declared duplicate secret slot %q", pluginName, typeName, name)
		}
		seenSlots[name] = true
	}

	seenEnv := map[string]bool{}
	for _, ev := range meta.envVars {
		name := strings.TrimSpace(ev.Name)
		if name == "" {
			return fail("plugin %q credential %q: build metadata declared empty env var name", pluginName, typeName)
		}
		if seenEnv[name] {
			return fail("plugin %q credential %q: build metadata declared duplicate env var %q", pluginName, typeName, name)
		}
		seenEnv[name] = true
	}
	return nil
}

func validateBuildDisambiguators(pluginName, typeName string, supported, got []string) hcl.Diagnostics {
	if len(got) == 0 {
		return nil
	}
	allowed := map[string]bool{}
	for _, s := range supported {
		allowed[s] = true
	}
	for _, s := range got {
		if !allowed[s] {
			return fail("plugin %q credential %q: build metadata declared unsupported disambiguator %q", pluginName, typeName, s)
		}
	}
	return nil
}

// =====================================================================
// Tunnel registration
// =====================================================================

func registerTunnel(client *Client, pluginName string, decl *pb.TunnelDecl) hcl.Diagnostics {
	if decl.Schema != nil {
		for _, f := range decl.Schema.Fields {
			if tunnelCommonReserved[f.Name] {
				// These are the framework-level tunnel attrs the loader peels
				// (decodeTunnelCommon); a plugin field by the same name would be
				// silently stolen. Reject at registration, like endpointSpec
				// rejects `hosts`/`dial`.
				return fail("plugin %q tunnel %q: declared reserved attribute %q (via / share / keepalive / credential are framework-level tunnel attrs)",
					pluginName, decl.TypeName, f.Name)
			}
		}
	}
	spec, err := schemaToSpec(decl.Schema)
	if err != nil {
		return fail("plugin %q tunnel %q: %v", pluginName, decl.TypeName, err)
	}
	adapter := &tunnelAdapter{client: client, typeName: decl.TypeName}

	plug := &config.Plugin{
		Kind: config.KindTunnel,
		Type: decl.TypeName,
		New:  func() any { return &dynamicTunnelBody{adapter: adapter} },
		DecodeBody: func(body hcl.Body, ctx *hcl.EvalContext, target any) hcl.Diagnostics {
			b := target.(*dynamicTunnelBody)
			// Peel the framework-level tunnel attrs (via / share / keepalive
			// / credential) before the schema decode — the plugin's manifest
			// schema doesn't know about them. TunnelCommon (on the body) hands
			// them to compile, which resolves `via`/`credential` by name.
			rest, d := decodeTunnelCommon(body, ctx, &b.common)
			if d.HasErrors() {
				return d
			}
			val, dd := hcldec.Decode(rest, spec, ctx)
			d = append(d, dd...)
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
	if d := registerOrCollide(plug, pluginName, "tunnel"); d != nil {
		return d
	}
	return nil
}

// decodeTunnelCommon peels the framework-level tunnel attrs (via, share,
// keepalive, credential) off a plugin tunnel block, fills tc, and returns
// the remainder body for the plugin's schema decode. via and credential
// are bare-name references that evaluate to the referenced block's name;
// the compile pass resolves them against the symbol table (and detects via
// cycles), exactly as for a built-in tunnel. Tunnels skip the loader's
// frameworkAttrsByKind extraction (it covers only endpoints/credentials),
// so the plugin decode peels them here.
// tunnelCommonReserved is the set of framework-level tunnel attr names
// decodeTunnelCommon peels — the names a plugin tunnel manifest may not
// reuse (enforced in registerTunnel).
var tunnelCommonReserved = map[string]bool{"via": true, "share": true, "keepalive": true, "credential": true}

func decodeTunnelCommon(body hcl.Body, ctx *hcl.EvalContext, tc *config.TunnelCommon) (hcl.Body, hcl.Diagnostics) {
	schema := &hcl.BodySchema{}
	for name := range tunnelCommonReserved {
		schema.Attributes = append(schema.Attributes, hcl.AttributeSchema{Name: name})
	}
	content, remain, diags := body.PartialContent(schema)
	for name, attr := range content.Attributes {
		v, d := attr.Expr.Value(ctx)
		diags = append(diags, d...)
		if d.HasErrors() || v.IsNull() {
			continue
		}
		if v.Type() != cty.String {
			rng := attr.Expr.Range()
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Invalid %s attribute", name),
				Detail:   fmt.Sprintf("Expected a string or bare-name reference; got %s.", v.Type().FriendlyName()),
				Subject:  &rng,
			})
			continue
		}
		switch name {
		case "via":
			tc.Via = v.AsString()
		case "share":
			tc.Share = v.AsString()
		case "keepalive":
			tc.Keepalive = v.AsString()
		case "credential":
			tc.Credential = v.AsString()
		}
	}
	return remain, diags
}

// =====================================================================
// Endpoint registration
// =====================================================================

// Reserved attribute names the framework injects on every external
// endpoint's body, regardless of what the plugin declared.
const (
	endpointAttrHosts = "hosts"
	// endpointAttrDial is the operator-written allow-list of extra
	// upstream targets the gateway will open for this endpoint
	// instance via the brokered dial. Entries are "host:port" or
	// "*.suffix.tld:port". Decoded by the gateway and stripped from
	// the canonical JSON — dial authorization must rest on HCL the
	// operator wrote, never on plugin-controlled config.
	endpointAttrDial = "dial"
)

func registerEndpoint(client *Client, pluginName string, decl *pb.EndpointDecl) hcl.Diagnostics {
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
		Type:   decl.TypeName,
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
			if dialV, ok := obj[endpointAttrDial]; ok && !dialV.IsNull() {
				for it := dialV.ElementIterator(); it.Next(); {
					_, dv := it.Element()
					entry := dv.AsString()
					if err := checkDialTarget(entry); err != nil {
						d = append(d, &hcl.Diagnostic{
							Severity: hcl.DiagError,
							Summary:  fmt.Sprintf("Invalid dial entry %q", entry),
							Detail:   err.Error(),
						})
						continue
					}
					b.dialTargets = append(b.dialTargets, entry)
				}
				if d.HasErrors() {
					return d
				}
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
			_ = ctx
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
	if d := registerOrCollide(plug, pluginName, "endpoint"); d != nil {
		return d
	}
	return nil
}

// registerOrCollide installs plug in the config registry or returns
// a diagnostic when something is already registered under the same
// (Kind, Type). Naming is flat — plugin authors prefix their types
// by convention, the way Terraform providers do (`aws_instance`,
// `kubernetes_deployment`) — so a collision either means two plugins
// picked the same type name or the plugin tried to shadow a
// built-in (e.g. `https`). Both are operator-actionable; neither is
// recoverable by the gateway.
func registerOrCollide(plug *config.Plugin, pluginName, kindLabel string) hcl.Diagnostics {
	if existing := config.Lookup(plug.Kind, plug.Type); existing != nil {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Plugin %q %s type %q collides with an already-registered type", pluginName, kindLabel, plug.Type),
			Detail:   "Type names live in one global registry — pick a different name (the convention is to prefix with the plugin slug, e.g. \"example_magic_token\"), or remove the conflicting registration.",
		}}
	}
	config.Register(plug)
	return nil
}

func init() {
	// Compile-time sanity: dynamicEndpointBody satisfies the
	// reflective interface compile.go expects.
	var _ interface {
		EndpointHosts() []string
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
// the plugin-declared fields plus the always-injected `hosts`
// attribute. The second return is the list of plugin-declared
// attribute names so the synthesized DecodeBody can strip the
// framework-injected ones before forwarding to Build.
func endpointSpec(s *pb.Schema) (hcldec.Spec, []string, error) {
	out := hcldec.ObjectSpec{
		endpointAttrHosts: &hcldec.AttrSpec{Name: endpointAttrHosts, Type: cty.List(cty.String), Required: true},
		endpointAttrDial:  &hcldec.AttrSpec{Name: endpointAttrDial, Type: cty.List(cty.String), Required: false},
	}
	var names []string
	if s != nil {
		for _, f := range s.Fields {
			if f.Name == endpointAttrHosts || f.Name == endpointAttrDial {
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
