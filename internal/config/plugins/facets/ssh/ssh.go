// Package ssh is the SSH protocol-family facet. It owns the SSH CEL
// environment (verb / command / subsystem / forward_host /
// forward_port / user, exposed as fields on the `ssh` variable), the
// matcher that walks a per-channel SSH action, the Meta type the ssh
// endpoint runtime populates on match.Request.Meta, and the
// per-family report fields the dashboard shows for an SSH action.
//
// Unlike https, an SSH connection has no single "request" — the agent
// opens channels and issues channel-requests (pty-req / exec / shell /
// subsystem) and direct-tcpip port forwards. The ssh endpoint runtime
// evaluates one match.Request per such action at the point the action
// crosses the gateway, deriving Meta from the wire envelope (RFC4254
// channel-open ExtraData and channel-request payloads), so
// PrepareRequest is a no-op.
//
// Scope: the facet gates the channel *envelope* — the action verb
// (pty / exec / shell / subsystem / forward), the exec command string,
// the subsystem name, the forward target. It does NOT inspect the
// bytes flowing inside a channel once it is open. Two consequences
// worth stating plainly:
//
//   - `ssh.command` is the literal command line the agent's client
//     sent. Matching on it is best-effort: the agent picks the string
//     (full paths, wrappers, shell builtins), so command rules are an
//     advisory / audit control, not a hard boundary.
//   - `ssh.verb == 'shell'` denies only the default-login-shell
//     request; it is NOT a robust "no interactive session" control,
//     because an exec'd shell (`ssh host bash`) is equally
//     interactive. The robust signal for an interactive *terminal* is
//     the pty allocation request: deny `ssh.verb == 'pty'` to refuse
//     any session that asks for a terminal — the endpoint tears the
//     channel down at the pty-req, before shell/exec runs.
package ssh

import (
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"

	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"
)

// Fields is the CEL-facing view of an SSH action. Exposed as the
// `ssh` variable in rule conditions (`ssh.verb`, `ssh.command`,
// `ssh.subsystem`, `ssh.forward_host`, `ssh.forward_port`,
// `ssh.user`). Only the field relevant to the action's verb is
// populated; the rest are zero (`""` / `0`), so a condition reading
// `ssh.command` on a `shell` action sees an empty string rather than
// failing to evaluate.
type Fields struct {
	Verb        string `cel:"verb"`         // pty | exec | shell | subsystem | forward
	Command     string `cel:"command"`      // exec argv as a single string
	Subsystem   string `cel:"subsystem"`    // subsystem name, e.g. "sftp"
	ForwardHost string `cel:"forward_host"` // direct-tcpip destination host
	ForwardPort int    `cel:"forward_port"` // direct-tcpip destination port
	User        string `cel:"user"`         // upstream SSH username
}

// Verb constants name the per-channel actions the ssh facet gates.
// The endpoint runtime stamps one onto each Meta it builds.
const (
	VerbPTY       = "pty"       // session channel-request `pty-req` (terminal)
	VerbExec      = "exec"      // session channel-request `exec` (a command)
	VerbShell     = "shell"     // session channel-request `shell` (default login shell)
	VerbSubsystem = "subsystem" // session channel-request `subsystem` (sftp, ...)
	VerbForward   = "forward"   // direct-tcpip channel open (port forward)
)

// Meta carries the per-action SSH fields the matcher reads. The ssh
// endpoint runtime builds one of these from the channel envelope and
// assigns it to match.Request.Meta. User is also mirrored onto
// match.Request.User (the canonical cross-protocol user field); the
// activation prefers the request-level value and falls back to Meta.
type Meta struct {
	Verb        string // one of the Verb* constants
	Command     string // exec command string; "" for non-exec verbs
	Subsystem   string // subsystem name; "" for non-subsystem verbs
	ForwardHost string // direct-tcpip dest host; "" for non-forward verbs
	ForwardPort uint32 // direct-tcpip dest port; 0 for non-forward verbs
	User        string // upstream username
}

// Facet is the SSH facet Runtime. Singleton.
type Facet struct{}

// Name reports the family identifier this facet handles. Must match
// the `Family: "ssh"` the ssh endpoint plugin declares.
func (Facet) Name() string { return "ssh" }

// EndpointFamilies enumerates endpoint families an ssh rule may
// attach to.
func (Facet) EndpointFamilies() []string { return []string{"ssh"} }

// Transport returns "" because SSH endpoints own their own
// wire-protocol handler (the gateway terminates SSH on both sides);
// they are not dispatched through the HTTPS-MITM SNI-peek path.
func (Facet) Transport() string { return "" }

// HITLQueryLabel is the dashboard / Slack label for an SSH action.
func (Facet) HITLQueryLabel() string { return "Command" }

// HostIsResource reports that an SSH request's Host is a wire-level
// address rather than a label the operator would recognise, so the
// dashboard substitutes the operator-defined endpoint name.
func (Facet) HostIsResource() bool { return false }

// ReportFields declares the per-family columns the SSH facet emits.
func (Facet) ReportFields() []facet.ReportFieldSpec {
	return []facet.ReportFieldSpec{
		{Name: "verb", Kind: facet.ReportString, Label: "Verb"},
		{Name: "command", Kind: facet.ReportString, Label: "Command"},
		{Name: "subsystem", Kind: facet.ReportString, Label: "Subsystem"},
		{Name: "forward_host", Kind: facet.ReportString, Label: "Forward host"},
		{Name: "forward_port", Kind: facet.ReportInt, Label: "Forward port"},
		{Name: "user", Kind: facet.ReportString, Label: "User"},
	}
}

// PrepareRequest is a no-op: the ssh endpoint runtime sets req.Meta
// directly from the channel envelope.
func (Facet) PrepareRequest(*match.Request) {}

// Report extracts the SSH report fields from a request. When Meta
// isn't a *Meta (e.g. a request that never ran through the ssh
// frontend) the result is empty rather than panicking.
func (Facet) Report(req *match.Request) map[string]any {
	m, _ := req.Meta.(*Meta)
	if m == nil {
		return nil
	}
	return map[string]any{
		"verb":         m.Verb,
		"command":      m.Command,
		"subsystem":    m.Subsystem,
		"forward_host": m.ForwardHost,
		"forward_port": int(m.ForwardPort),
		"user":         userOf(req, m),
	}
}

// userOf returns the action's upstream user, preferring the
// request-level field (the canonical cross-protocol User) and
// falling back to meta.User. Mirrors sql.databaseOf.
func userOf(req *match.Request, m *Meta) string {
	if req != nil && req.User != "" {
		return req.User
	}
	if m != nil {
		return m.User
	}
	return ""
}

func init() {
	facet.Register(Facet{})
}

// CELContrib declares the SSH facet's CEL contribution: the `ssh`
// variable backed by Fields and the path lists CompileCondition needs.
//
// lowercasedPaths: ssh.verb's activation value is lowercased so a
// rule written as `ssh.verb == "Shell"` still matches. command,
// subsystem, and forward_host are intentionally case-sensitive —
// program names and hostnames are matched as sent.
//
// truncatablePaths / unparseablePaths: empty. Every ssh field comes
// from a small, fully-read channel envelope (the channel-open
// ExtraData or the channel-request payload), never from a capped
// inspection buffer or a fallible parser, so no field can be a ghost
// value that needs a fail-closed deny.
func (Facet) CELContrib() facet.CELContrib {
	return facet.CELContrib{
		EnvOptions: []cel.EnvOption{
			ext.NativeTypes(
				reflect.TypeFor[Fields](),
				ext.ParseStructTags(true),
			),
			cel.Variable("ssh", cel.ObjectType("ssh.Fields")),
		},
		AddActivation:   addActivation,
		LowercasedPaths: []string{"ssh.verb"},
	}
}

// NewMatcher compiles a CEL condition into a Matcher. Delegates to
// the package-level composer; the ssh family composes only its own
// ssh facet (SSH is not layered over HTTPS, so there is no http facet
// to add).
func (f Facet) NewMatcher(condition string) (match.Matcher, error) {
	m, _, err := facet.Compose(f.Name(), condition)
	return m, err
}

func addActivation(req *match.Request, act map[string]any) bool {
	if req == nil {
		return false
	}
	meta, _ := req.Meta.(*Meta)
	if meta == nil {
		return false
	}
	act["ssh"] = &Fields{
		Verb:        strings.ToLower(meta.Verb),
		Command:     meta.Command,
		Subsystem:   meta.Subsystem,
		ForwardHost: meta.ForwardHost,
		ForwardPort: int(meta.ForwardPort),
		User:        userOf(req, meta),
	}
	return true
}
