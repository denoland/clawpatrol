package extplugin

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
)

func mfPrivileged(privileged bool) *pb.ManifestResponse {
	return &pb.ManifestResponse{
		Name:         "p",
		Capabilities: &pb.PluginCapabilities{Privileged: privileged},
	}
}

func newPrivTestManager(t *testing.T) *Manager {
	t.Helper()
	m := New(nil)
	m.lock.configure(filepath.Join(t.TempDir(), LockfileName), false)
	if err := m.lock.load(); err != nil {
		t.Fatal(err)
	}
	return m
}

// A plugin that declares the privileged capability is held closed until the
// operator approves it explicitly; resolvePrivileged never records the grant
// on its own (unlike network/egress trust-on-first-use).
func TestResolvePrivilegedFailsClosedUntilApproved(t *testing.T) {
	m := newPrivTestManager(t)
	sp := config.PluginSource{Name: "p", Source: "github.com/o/p"}

	call := func(hash string, declared bool) (bool, string, error) {
		prior, priorRec := m.lock.get(sp.Name)
		return m.resolvePrivileged(sp, prior, priorRec, hash, mfPrivileged(declared))
	}

	// First load of a privileged plugin: fail closed, nothing recorded.
	if _, _, err := call("sha256:v1", true); err == nil ||
		!strings.Contains(err.Error(), "privileged capability") {
		t.Fatalf("first load err = %v, want fail-closed", err)
	}
	if e, ok := m.lock.get("p"); ok && e.Privileged {
		t.Fatalf("resolvePrivileged must not record the grant itself: %+v", e)
	}

	// Operator approves: records the hash + privileged flag (as Approve does).
	m.lock.addHash(sp.Name, "sha256:v1", "none")
	m.lock.setPrivileged(sp.Name, true)

	// Fast path: the approved binary now runs privileged, no error.
	prior, priorRec := m.lock.get(sp.Name)
	off, _, err := m.resolvePrivileged(sp, prior, priorRec, "sha256:v1", nil)
	if err != nil || !off {
		t.Fatalf("approved fast path = %v err=%v, want true", off, err)
	}

	// An upgrade (new hash) re-pends approval: the prior snapshot does not
	// record sha256:v2, so it fails closed even though Privileged is set.
	if _, _, err := call("sha256:v2", true); err == nil ||
		!strings.Contains(err.Error(), "privileged capability") {
		t.Fatalf("upgrade err = %v, want fail-closed", err)
	}
}

// A plugin that does not declare the capability runs sandboxed with no
// approval needed.
func TestResolvePrivilegedNotDeclared(t *testing.T) {
	m := newPrivTestManager(t)
	sp := config.PluginSource{Name: "p", Source: "github.com/o/p"}
	prior, priorRec := m.lock.get(sp.Name)
	off, warn, err := m.resolvePrivileged(sp, prior, priorRec, "sha256:v1", mfPrivileged(false))
	if err != nil || off || warn != "" {
		t.Fatalf("not declared = %v warn=%q err=%v, want false", off, warn, err)
	}
}

// The operator's own `sandbox = "off"` HCL is an explicit, committed
// acceptance that wins outright — no lockfile approval, no manifest check.
func TestResolvePrivilegedOperatorOverride(t *testing.T) {
	m := newPrivTestManager(t)
	sp := config.PluginSource{Name: "p", Source: "github.com/o/p", Sandbox: "off"}
	prior, priorRec := m.lock.get(sp.Name)
	off, _, err := m.resolvePrivileged(sp, prior, priorRec, "sha256:v1", nil)
	if err != nil || !off {
		t.Fatalf("operator sandbox=off = %v err=%v, want true", off, err)
	}
}

// Without a lockfile there is no approval channel, so a declared privileged
// plugin runs unsandboxed directly (the same "trust the declaration, no
// enforcement" behaviour network/egress have without a lockfile).
func TestResolvePrivilegedNoLockfile(t *testing.T) {
	m := New(nil) // no lockfile configured
	sp := config.PluginSource{Name: "p", Source: "github.com/o/p"}
	prior, priorRec := m.lock.get(sp.Name)
	off, warn, err := m.resolvePrivileged(sp, prior, priorRec, "sha256:v1", mfPrivileged(true))
	if err != nil || !off || warn == "" {
		t.Fatalf("no lockfile = %v warn=%q err=%v, want true with warn", off, warn, err)
	}
}

// A binary approved without the privileged flag (e.g. it did not declare the
// capability when approved) that now declares it must fail closed, even
// though its hash is in the approved set.
func TestResolvePrivilegedApprovedHashButFlagUnset(t *testing.T) {
	m := newPrivTestManager(t)
	sp := config.PluginSource{Name: "p", Source: "github.com/o/p"}
	// Hash recorded, but Privileged never set.
	m.lock.addHash(sp.Name, "sha256:v1", "none")

	prior, priorRec := m.lock.get(sp.Name)
	off, _, err := m.resolvePrivileged(sp, prior, priorRec, "sha256:v1", mfPrivileged(true))
	// Fast path reads the recorded flag (false) — the binary runs sandboxed.
	if err != nil || off {
		t.Fatalf("flag-unset fast path = %v err=%v, want false (sandboxed)", off, err)
	}
}
