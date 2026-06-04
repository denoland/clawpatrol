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
	if m.Match(shell).Result != match.Matched {
		t.Errorf("expected shell to match ssh.verb == 'shell'")
	}
	if got := m.Match(exec).Result; got != match.NoMatch {
		t.Errorf("expected exec to NOT match ssh.verb == 'shell', got %v", got)
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
			if got := m.Match(req).Result; got != match.ResultOf(tc.want) {
				t.Errorf("Match=%v want %v", got, match.ResultOf(tc.want))
			}
		})
	}
}

// TestSSHMatcherPTY covers the robust "block interactive" condition:
// a `ssh.verb == 'pty'` rule fires on a pty-req (the terminal-request
// the endpoint gates before any shell/exec runs) and not on a plain
// command.
func TestSSHMatcherPTY(t *testing.T) {
	m := mustMatcher(t, "ssh.verb == 'pty'")
	pty := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{Verb: sshfacet.VerbPTY}}
	exec := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{Verb: sshfacet.VerbExec, Command: "uname -a"}}
	if m.Match(pty).Result != match.Matched {
		t.Errorf("expected pty-req to match ssh.verb == 'pty'")
	}
	if got := m.Match(exec).Result; got != match.NoMatch {
		t.Errorf("expected a command to NOT match ssh.verb == 'pty', got %v", got)
	}
}

// TestSSHMatcherCommand covers command-string matching (an advisory /
// audit control — the agent picks the string, so it is best-effort,
// not a hard boundary). Matching is case-sensitive.
func TestSSHMatcherCommand(t *testing.T) {
	m := mustMatcher(t, "ssh.verb == 'exec' && ssh.command.startsWith('backup ')")
	backup := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{
		Verb: sshfacet.VerbExec, Command: "backup --full /data",
	}}
	restore := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{
		Verb: sshfacet.VerbExec, Command: "restore --all /data",
	}}
	if m.Match(backup).Result != match.Matched {
		t.Errorf("expected `backup ...` to match")
	}
	if got := m.Match(restore).Result; got != match.NoMatch {
		t.Errorf("expected `restore ...` to NOT match, got %v", got)
	}
}

// TestSSHMatcherSubsystem blocks the sftp subsystem while leaving
// other actions alone.
func TestSSHMatcherSubsystem(t *testing.T) {
	m := mustMatcher(t, "ssh.subsystem == 'sftp'")
	sftp := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{Verb: sshfacet.VerbSubsystem, Subsystem: "sftp"}}
	shell := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{Verb: sshfacet.VerbShell}}
	if m.Match(sftp).Result != match.Matched {
		t.Errorf("expected sftp subsystem to match")
	}
	if got := m.Match(shell).Result; got != match.NoMatch {
		t.Errorf("expected shell to NOT match a subsystem condition, got %v", got)
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
	if m.Match(pg).Result != match.Matched {
		t.Errorf("expected forward to :5432 to match")
	}
	if got := m.Match(web).Result; got != match.NoMatch {
		t.Errorf("expected forward to :8080 to NOT match, got %v", got)
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
	if m.Match(fromReq).Result != match.Matched {
		t.Errorf("expected req.User=deploy to match")
	}
	if m.Match(fromMeta).Result != match.Matched {
		t.Errorf("expected meta.User=deploy fallback to match")
	}
	if got := m.Match(other).Result; got != match.NoMatch {
		t.Errorf("expected req.User to win over meta.User, got %v", got)
	}
}

// TestSSHMatcherWrongMeta confirms a non-ssh Meta is Unevaluable
// (the activation builder refuses, and the dispatcher fails closed)
// rather than panicking or silently no-matching — e.g. if an ssh
// rule somehow saw a request without a *Meta.
func TestSSHMatcherWrongMeta(t *testing.T) {
	m := mustMatcher(t, "ssh.verb == 'shell'")
	req := &match.Request{Family: "ssh", Meta: struct{}{}}
	if got := m.Match(req).Result; got != match.Unevaluable {
		t.Errorf("expected non-ssh Meta to be Unevaluable, got %v", got)
	}
	if got := m.Match(&match.Request{Family: "ssh"}).Result; got != match.Unevaluable {
		t.Errorf("expected nil Meta to be Unevaluable, got %v", got)
	}
}

// TestSSHEmptyConditionMatchesEverything is the catch-all contract: an
// empty condition compiles to a pass-through matcher (used by
// `verdict = "deny"` default rules with no condition).
func TestSSHEmptyConditionMatchesEverything(t *testing.T) {
	m := mustMatcher(t, "")
	req := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{Verb: sshfacet.VerbExec, Command: "anything"}}
	if m.Match(req).Result != match.Matched {
		t.Errorf("expected empty condition to match everything")
	}
}

// TestSSHStdinMatch covers matching the buffered session stdin — the
// pre-gated body of `ssh host < script`.
func TestSSHStdinMatch(t *testing.T) {
	m := mustMatcher(t, "ssh.stdin.contains('rm -rf /')")
	bad := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{
		Verb: sshfacet.VerbShell, Stdin: "#!/bin/sh\nrm -rf / --no-preserve-root\n",
	}}
	ok := &match.Request{Family: "ssh", Meta: &sshfacet.Meta{
		Verb: sshfacet.VerbShell, Stdin: "#!/bin/sh\necho hello\n",
	}}
	if m.Match(bad).Result != match.Matched {
		t.Errorf("expected a destructive script to match ssh.stdin.contains(...)")
	}
	if got := m.Match(ok).Result; got != match.NoMatch {
		t.Errorf("expected a benign script to NOT match, got %v", got)
	}
}

// TestSSHStdinIsTruncatable pins the wiring that makes lazy buffering
// work: a rule reading ssh.stdin reports InspectsTruncatableFacet()
// (so CompiledEndpoint.InspectsTruncatable flips and the endpoint
// takes the buffering path; overflow then fail-closes through the
// matcher's stdin-unknown), while a rule that doesn't read stdin does
// not — keeping the splice on the zero-overhead fast path.
func TestSSHStdinIsTruncatable(t *testing.T) {
	if !mustMatcher(t, "ssh.stdin.contains('x')").InspectsTruncatableFacet() {
		t.Error("ssh.stdin rule should report InspectsTruncatableFacet() == true")
	}
	if mustMatcher(t, "ssh.verb == 'exec' && ssh.command == 'x'").InspectsTruncatableFacet() {
		t.Error("a non-stdin rule should report InspectsTruncatableFacet() == false")
	}
	if mustMatcher(t, "").InspectsTruncatableFacet() {
		t.Error("the catch-all matcher should report InspectsTruncatableFacet() == false")
	}
}
