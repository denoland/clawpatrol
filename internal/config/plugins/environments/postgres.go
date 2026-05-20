package environments

// postgres_environment: libpq env vars (PGHOST, PGPORT, PGUSER,
// PGDATABASE, PGPASSWORD) derived from a (postgres endpoint,
// postgres credential) pair. PGPASSWORD lands as a placeholder
// (the credential's bound user is the dispatch discriminator the
// MITM path uses on the wire); the real password is delivered via
// the bound postgres_credential plugin's wire-level injection, not
// via the env.
//
// PGHOST/PGPORT come from the endpoint's `host = "<host>:<port>"`;
// PGUSER/PGDATABASE come from the credential's own fields.
//
// Sample HCL:
//
//	endpoint "postgres" "pg" {
//	  host = "pg.internal.example.com:5432"
//	}
//
//	credential "postgres_credential" "pg-rw" {
//	  endpoint = postgres.pg
//	  user     = "agent_rw"
//	  database = "appdb"
//	}
//
//	environment "postgres_environment" "pg-rw-env" {
//	  endpoint   = postgres.pg
//	  credential = postgres_credential.pg-rw
//	}
//
//	profile "alice" {
//	  credentials  = [postgres_credential.pg-rw]
//	  environments = [postgres_environment.pg-rw-env]
//	}

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"

	"github.com/denoland/clawpatrol/internal/config"
)

// phPostgres is the PGPASSWORD placeholder. Chosen for the same
// reason as the per-provider HTTP token placeholders: looks like a
// real string so libpq's parser doesn't reject it before the
// connection is even attempted; the gateway swaps it for the real
// secret on the wire.
const phPostgres = "clawpatrol-pg-placeholder-do-not-use"

// PostgresEnvironment is part of the clawpatrol plugin API. The
// resolved Endpoint / Credential entities are stashed here at
// build time so EnvVars() can read host / port / user / database
// without re-walking the symbol table on every call.
type PostgresEnvironment struct {
	endpointHost     string // includes :port when set
	credentialUser   string
	credentialDBName string
}

// EnvVars is part of the clawpatrol plugin API.
func (p *PostgresEnvironment) EnvVars() []config.EnvVar {
	if p == nil {
		return nil
	}
	host, port := splitHostPort(p.endpointHost)
	var out []config.EnvVar
	if host != "" {
		out = append(out, config.EnvVar{Name: "PGHOST", Value: host, Description: "from postgres endpoint host"})
	}
	if port != "" {
		out = append(out, config.EnvVar{Name: "PGPORT", Value: port, Description: "from postgres endpoint host"})
	}
	if p.credentialUser != "" {
		out = append(out, config.EnvVar{Name: "PGUSER", Value: p.credentialUser, Description: "from postgres credential"})
	}
	if p.credentialDBName != "" {
		out = append(out, config.EnvVar{Name: "PGDATABASE", Value: p.credentialDBName, Description: "from postgres credential"})
	}
	out = append(out, config.EnvVar{
		Name:        "PGPASSWORD",
		Value:       phPostgres,
		Description: "placeholder — real password supplied by the bound credential at MITM time",
	})
	return out
}

func postgresBuild(decoded any, name string, ctx *config.BuildCtx) (any, hcl.Diagnostics) {
	p, ok := decoded.(*PostgresEnvironment)
	if !ok {
		return decoded, nil
	}
	var diags hcl.Diagnostics

	epRef := ctx.Framework.Ref("endpoint")
	credRef := ctx.Framework.Ref("credential")
	if epRef == "" {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("environment %q: postgres_environment requires `endpoint = postgres.<name>`", name),
			Subject:  &ctx.Block.DefRange,
		})
	}
	if credRef == "" {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("environment %q: postgres_environment requires `credential = postgres_credential.<name>`", name),
			Subject:  &ctx.Block.DefRange,
		})
	}
	if diags.HasErrors() {
		return p, diags
	}

	// Pull host off the endpoint plugin's decoded body. The plugin
	// types live in internal/config/plugins/endpoints, but we can't
	// import them (would cycle); use reflection via a typed string
	// extraction helper that asks the symbol's Block for the `host`
	// attribute. Cheaper alternative: declare a tiny interface here.
	//
	// We can read it off the resolved Symbol's Block body via the
	// `host = "..."` attr directly without referencing the plugin
	// type.
	epSym := ctx.Symbols.Get(config.KindEndpoint, epRef)
	if epSym != nil {
		p.endpointHost = readStringAttr(epSym.Block.Body, "host")
	}
	credSym := ctx.Symbols.Get(config.KindCredential, credRef)
	if credSym != nil {
		p.credentialUser = readStringAttr(credSym.Block.Body, "user")
		p.credentialDBName = readStringAttr(credSym.Block.Body, "database")
	}
	return p, diags
}

// splitHostPort returns (host, port) for a `"host:port"` or
// `"host"` string. Port is "" when not present. IPv6 brackets
// (`[::1]:5432`) are stripped.
func splitHostPort(s string) (string, string) {
	if s == "" {
		return "", ""
	}
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return s, ""
		}
		host := s[1:end]
		rest := s[end+1:]
		if strings.HasPrefix(rest, ":") {
			return host, rest[1:]
		}
		return host, ""
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

func init() {
	var _ config.EnvironmentRuntime = (*PostgresEnvironment)(nil)
	config.Register(&config.Plugin{
		Kind:  config.KindEnvironment,
		Type:  "postgres_environment",
		New:   newer[PostgresEnvironment](),
		Build: postgresBuild,
		Emit:  emptyEmit,
	})
}
