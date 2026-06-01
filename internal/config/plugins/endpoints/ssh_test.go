package endpoints

import (
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/denoland/clawpatrol/internal/config"
	sshfacet "github.com/denoland/clawpatrol/internal/config/plugins/facets/ssh"
)

// pickSSHCredential covers the multi-credential dispatch contract:
// * exact-user match wins
// * catchall (no Placeholder) is the fallback
// * profile with no credential binding → nil
// * single no-Placeholder entry → that entry, regardless of agent user
// * no match + no fallback → nil
func TestPickSSHCredential(t *testing.T) {
	mk := func(user, name string) *config.CompiledCredential {
		c := &config.CompiledCredential{
			Credential: &config.Entity{
				Symbol: &config.Symbol{Kind: config.KindCredential, Type: "ssh_key", Name: name},
			},
		}
		if user != "" {
			c.Disambiguators = map[string]string{"user": user}
		}
		return c
	}
	cases := []struct {
		name  string
		creds []*config.CompiledCredential
		user  string
		want  string // expected credential name; "" for nil
	}{
		{"empty list", nil, "anybody", ""},
		{"singular catchall — matches any user", []*config.CompiledCredential{mk("", "default")}, "anybody", "default"},
		{"singular catchall — empty user", []*config.CompiledCredential{mk("", "default")}, "", "default"},
		{
			"multi: exact match",
			[]*config.CompiledCredential{
				mk("root", "root-cred"),
				mk("deploy", "deploy-cred"),
				mk("", "fallback-cred"),
			},
			"deploy",
			"deploy-cred",
		},
		{
			"multi: fallback when no exact match",
			[]*config.CompiledCredential{
				mk("root", "root-cred"),
				mk("deploy", "deploy-cred"),
				mk("", "fallback-cred"),
			},
			"alice",
			"fallback-cred",
		},
		{
			"multi: no match + no fallback → nil",
			[]*config.CompiledCredential{
				mk("root", "root-cred"),
				mk("deploy", "deploy-cred"),
			},
			"alice",
			"",
		},
		{
			"multi: matched user takes precedence over catchall order",
			[]*config.CompiledCredential{
				mk("", "fallback-cred"),
				mk("root", "root-cred"),
			},
			"root",
			"root-cred",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ep := &config.CompiledEndpoint{Name: "ep"}
			prof := &config.CompiledProfile{
				Name: "p",
				EndpointCredentials: map[string][]*config.CompiledCredential{
					"ep": c.creds,
				},
			}
			policy := &config.CompiledPolicy{
				Profiles: map[string]*config.CompiledProfile{"p": prof},
			}
			got := pickSSHCredential(policy, "p", ep, c.user)
			if c.want == "" {
				if got != nil {
					t.Fatalf("expected nil; got %q", got.Credential.Symbol.Name)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected %q; got nil", c.want)
			}
			if got.Credential.Symbol.Name != c.want {
				t.Fatalf("expected %q; got %q", c.want, got.Credential.Symbol.Name)
			}
		})
	}
}

// metaForChannelReq covers the per-channel requests an agent can
// send: exec carries argv as one string, shell is empty, subsystem
// carries the subsystem name, anything else (pty-req, env,
// window-change, signal, ...) is dropped silently. The derived Meta's
// verb-relevant field and the sshSummary one-liner are both checked.
func TestMetaForChannelReq(t *testing.T) {
	cases := []struct {
		name        string
		reqType     string
		payload     []byte
		wantOK      bool
		wantVerb    string
		wantCommand string
		wantSubsys  string
		wantSummary string
	}{
		{
			name:        "exec",
			reqType:     "exec",
			payload:     ssh.Marshal(execPayload{Command: "ls -la /etc"}),
			wantOK:      true,
			wantVerb:    sshfacet.VerbExec,
			wantCommand: "ls -la /etc",
			wantSummary: "ls -la /etc",
		},
		{
			name:        "shell",
			reqType:     "shell",
			payload:     nil,
			wantOK:      true,
			wantVerb:    sshfacet.VerbShell,
			wantSummary: "interactive shell",
		},
		{
			name:        "subsystem sftp",
			reqType:     "subsystem",
			payload:     ssh.Marshal(subsystemPayload{Name: "sftp"}),
			wantOK:      true,
			wantVerb:    sshfacet.VerbSubsystem,
			wantSubsys:  "sftp",
			wantSummary: "sftp",
		},
		{name: "pty-req dropped", reqType: "pty-req", payload: nil, wantOK: false},
		{name: "env dropped", reqType: "env", payload: nil, wantOK: false},
		{name: "window-change dropped", reqType: "window-change", payload: nil, wantOK: false},
		{name: "exec with malformed payload", reqType: "exec", payload: []byte{0xff}, wantOK: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, ok := metaForChannelReq(&ssh.Request{Type: c.reqType, Payload: c.payload})
			if ok != c.wantOK {
				t.Fatalf("ok = %v; want %v", ok, c.wantOK)
			}
			if !ok {
				return
			}
			if m.Verb != c.wantVerb {
				t.Errorf("verb = %q; want %q", m.Verb, c.wantVerb)
			}
			if m.Command != c.wantCommand {
				t.Errorf("command = %q; want %q", m.Command, c.wantCommand)
			}
			if m.Subsystem != c.wantSubsys {
				t.Errorf("subsystem = %q; want %q", m.Subsystem, c.wantSubsys)
			}
			if got := sshSummary(m); got != c.wantSummary {
				t.Errorf("summary = %q; want %q", got, c.wantSummary)
			}
		})
	}
}

// classifyUpstreamChannelReq surfaces exit-status only.
func TestClassifyUpstreamChannelReq(t *testing.T) {
	t.Run("exit-status", func(t *testing.T) {
		ev, ok := classifyUpstreamChannelReq(&ssh.Request{
			Type:    "exit-status",
			Payload: ssh.Marshal(exitStatusPayload{Status: 127}),
		})
		if !ok {
			t.Fatal("expected event for exit-status")
		}
		if ev.Verb != "exit" || ev.Summary != "exit 127" {
			t.Errorf("got verb=%q summary=%q; want verb=exit summary=\"exit 127\"", ev.Verb, ev.Summary)
		}
	})
	t.Run("signal dropped", func(t *testing.T) {
		if _, ok := classifyUpstreamChannelReq(&ssh.Request{Type: "signal"}); ok {
			t.Fatal("expected signal to be dropped")
		}
	})
}

// metaForChannelOpen surfaces direct-tcpip targets; session opens
// (the common case for interactive logins / exec) are dropped — the
// interesting intent rides on the following channel-request.
func TestMetaForChannelOpen(t *testing.T) {
	t.Run("direct-tcpip", func(t *testing.T) {
		nc := fakeNewChannel{
			ty: "direct-tcpip",
			extra: ssh.Marshal(directTCPIPPayload{
				DestHost: "db.internal", DestPort: 5432,
				OriginHost: "127.0.0.1", OriginPort: 54321,
			}),
		}
		m, ok := metaForChannelOpen(nc)
		if !ok {
			t.Fatal("expected meta for direct-tcpip")
		}
		if m.Verb != sshfacet.VerbForward || m.ForwardHost != "db.internal" || m.ForwardPort != 5432 {
			t.Errorf("got verb=%q host=%q port=%d; want forward db.internal 5432", m.Verb, m.ForwardHost, m.ForwardPort)
		}
		if got := sshSummary(m); got != "→ db.internal:5432" {
			t.Errorf("summary = %q; want \"→ db.internal:5432\"", got)
		}
	})
	t.Run("session dropped", func(t *testing.T) {
		if _, ok := metaForChannelOpen(fakeNewChannel{ty: "session"}); ok {
			t.Fatal("expected session open to be dropped")
		}
	})
}

// fakeNewChannel is the minimum ssh.NewChannel surface
// metaForChannelOpen reads — type and ExtraData. Accept / Reject
// aren't exercised by the classifier.
type fakeNewChannel struct {
	ty    string
	extra []byte
}

func (f fakeNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, nil
}
func (f fakeNewChannel) Reject(ssh.RejectionReason, string) error { return nil }
func (f fakeNewChannel) ChannelType() string                      { return f.ty }
func (f fakeNewChannel) ExtraData() []byte                        { return f.extra }
