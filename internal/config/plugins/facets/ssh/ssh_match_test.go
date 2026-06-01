package ssh_test

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"
	sshfacet "github.com/denoland/clawpatrol/internal/config/plugins/facets/ssh"
)

func mustMatcher(t *testing.T, cond string) match.Matcher {
	t.Helper()
	m, err := facet.NewMatcher("ssh", cond)
	if err != nil {
		t.Fatalf("NewMatcher(%q): %v", cond, err)
	}
	return m
}

// TestSSHMatcherVerb is the headline use case: block interactive
// sessions while allowing one-shot commands. A `ssh.verb == 'shell'`
// rule fires on a shell action and not on an exec.
func TestSSHMatcherVerb(t *testing.T) {
	m := mustMatcher(t, "ssh.verb == 'shell'")
	shell := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{Verb: sshfacet.VerbShell}}
	exec := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{Verb: sshfacet.VerbExec, Command: "ls"}}
	if !m.Match(shell) {
		t.Errorf("expected shell to match ssh.verb == 'shell'")
	}
	if m.Match(exec) {
		t.Errorf("expected exec to NOT match ssh.verb == 'shell'")
	}
}

// TestSSHMatcherVerbCaseInsensitive locks in that a rule written with
// any casing on the verb literal matches — ssh.verb is lowercased at
// rule-load time, mirroring sql.verb.
func TestSSHMatcherVerbCaseInsensitive(t *testing.T) {
	cases := []struct {
		cond string
		want bool
	}{
		{"ssh.verb == 'SHELL'", true},
		{"ssh.verb == 'Shell'", true},
		{"ssh.verb == 'shell'", true},
		{"ssh.verb in ['SHELL', 'EXEC']", true},
		{"ssh.verb == 'EXEC'", false},
	}
	for _, tc := range cases {
		t.Run(tc.cond, func(t *testing.T) {
			m := mustMatcher(t, tc.cond)
			req := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{Verb: sshfacet.VerbShell}}
			if got := m.Match(req); got != tc.want {
				t.Errorf("Match=%v want %v", got, tc.want)
			}
		})
	}
}

// TestSSHMatcherCommand covers tier-2 command gating: block all git
// pushes by matching the receive-pack program, regardless of the repo
// path argument. The command is case-sensitive (program names are
// matched as sent).
func TestSSHMatcherCommand(t *testing.T) {
	m := mustMatcher(t, "ssh.verb == 'exec' && ssh.command.startsWith('git-receive-pack')")
	push := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{
		Verb: sshfacet.VerbExec, Command: "git-receive-pack '/srv/git/app.git'",
	}}
	fetch := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{
		Verb: sshfacet.VerbExec, Command: "git-upload-pack '/srv/git/app.git'",
	}}
	if !m.Match(push) {
		t.Errorf("expected receive-pack to match")
	}
	if m.Match(fetch) {
		t.Errorf("expected upload-pack to NOT match (reads are allowed)")
	}
}

// TestSSHMatcherSubsystem blocks the sftp subsystem while leaving
// other actions alone.
func TestSSHMatcherSubsystem(t *testing.T) {
	m := mustMatcher(t, "ssh.subsystem == 'sftp'")
	sftp := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{Verb: sshfacet.VerbSubsystem, Subsystem: "sftp"}}
	shell := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{Verb: sshfacet.VerbShell}}
	if !m.Match(sftp) {
		t.Errorf("expected sftp subsystem to match")
	}
	if m.Match(shell) {
		t.Errorf("expected shell to NOT match a subsystem condition")
	}
}

// TestSSHMatcherForwardPort gates a direct-tcpip port forward by its
// destination port. The port is exposed as a CEL int so a bare
// integer literal compares directly.
func TestSSHMatcherForwardPort(t *testing.T) {
	m := mustMatcher(t, "ssh.verb == 'forward' && ssh.forward_port == 5432")
	pg := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{
		Verb: sshfacet.VerbForward, ForwardHost: "db.internal", ForwardPort: 5432,
	}}
	web := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{
		Verb: sshfacet.VerbForward, ForwardHost: "db.internal", ForwardPort: 8080,
	}}
	if !m.Match(pg) {
		t.Errorf("expected forward to :5432 to match")
	}
	if m.Match(web) {
		t.Errorf("expected forward to :8080 to NOT match")
	}
}

// TestSSHMatcherUserFromRequest pins that ssh.user reads the
// request-level User (the canonical cross-protocol field the endpoint
// sets) and falls back to Meta.User.
func TestSSHMatcherUserFromRequest(t *testing.T) {
	m := mustMatcher(t, "ssh.user == 'deploy'")
	fromReq := &match.Request{Family: "ssh", User: "deploy", Meta: &sshfacet.Meta{Verb: sshfacet.VerbShell}}
	fromMeta := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{Verb: sshfacet.VerbShell, User: "deploy"}}
	other := &match.Request{Family: "ssh", User: "intern", Meta: &sshfacet.Meta{Verb: sshfacet.VerbShell, User: "deploy"}}
	if !m.Match(fromReq) {
		t.Errorf("expected req.User=deploy to match")
	}
	if !m.Match(fromMeta) {
		t.Errorf("expected meta.User=deploy fallback to match")
	}
	if m.Match(other) {
		t.Errorf("expected req.User to win over meta.User")
	}
}

// TestSSHMatcherWrongMeta confirms a non-ssh Meta fails the match
// cleanly (the activation builder refuses), rather than panicking —
// e.g. if an ssh rule somehow saw a request without a *Meta.
func TestSSHMatcherWrongMeta(t *testing.T) {
	m := mustMatcher(t, "ssh.verb == 'shell'")
	req := &match.Request{Family: "ssh", Meta: struct{}{}}
	if m.Match(req) {
		t.Errorf("expected non-ssh Meta to fail the match")
	}
	if m.Match(&match.Request{Family: "ssh"}) {
		t.Errorf("expected nil Meta to fail the match")
	}
}

// TestSSHEmptyConditionMatchesEverything is the catch-all contract: an
// empty condition compiles to a pass-through matcher (used by
// `verdict = "deny"` default rules with no condition).
func TestSSHEmptyConditionMatchesEverything(t *testing.T) {
	m := mustMatcher(t, "")
	req := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{Verb: sshfacet.VerbExec, Command: "anything"}}
	if !m.Match(req) {
		t.Errorf("expected empty condition to match everything")
	}
}
