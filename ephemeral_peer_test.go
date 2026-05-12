package main

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// TestLookupEphemeralPeerIgnoresNonEphemeralRows ensures the reuse
// check refuses to clobber a parent device's pubkey row — only rows
// flagged ephemeral=1 are eligible.
func TestLookupEphemeralPeerIgnoresNonEphemeralRows(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(
		`INSERT INTO wg_peers (pubkey, ip, added_ns, ephemeral) VALUES (?, ?, ?, 0)`,
		"parentpub", "10.55.0.10", time.Now().UnixNano(),
	); err != nil {
		t.Fatalf("seed parent: %v", err)
	}
	if _, _, ok := lookupEphemeralPeer(db, "parentpub"); ok {
		t.Error("non-ephemeral row matched ephemeral lookup")
	}

	if _, err := db.Exec(
		`INSERT INTO wg_peers (pubkey, ip, added_ns, ephemeral, parent_ip) VALUES (?, ?, ?, 1, ?)`,
		"ephpub", "10.55.0.42", time.Now().UnixNano(), "10.55.0.10",
	); err != nil {
		t.Fatalf("seed ephemeral: %v", err)
	}
	ip, parent, ok := lookupEphemeralPeer(db, "ephpub")
	if !ok || ip != "10.55.0.42" || parent != "10.55.0.10" {
		t.Errorf("lookupEphemeralPeer = (%q, %q, %v); want (10.55.0.42, 10.55.0.10, true)",
			ip, parent, ok)
	}

	if _, _, ok := lookupEphemeralPeer(db, "unknown"); ok {
		t.Error("unknown pubkey matched")
	}
}

// TestEvictEphemeralsForParentScoping ensures eviction is scoped to
// one parent_ip — sibling devices on the same gateway keep their
// ephemerals when this parent's cache is invalidated, and the parent
// device row itself is never touched.
func TestEvictEphemeralsForParentScoping(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	type row struct {
		pub, ip, parent string
		ephemeral       int
	}
	for _, r := range []row{
		{"hostA_eph", "10.55.0.20", "10.55.0.5", 1},
		{"hostB_eph", "10.55.0.21", "10.55.0.6", 1},
		{"hostA_perm", "10.55.0.5", "", 0}, // parent itself; must NOT be evicted
	} {
		var parent any = r.parent
		if r.parent == "" {
			parent = nil
		}
		if _, err := db.Exec(
			`INSERT INTO wg_peers (pubkey, ip, added_ns, ephemeral, parent_ip) VALUES (?, ?, ?, ?, ?)`,
			r.pub, r.ip, time.Now().UnixNano(), r.ephemeral, parent,
		); err != nil {
			t.Fatalf("seed %s: %v", r.pub, err)
		}
	}

	g := &Gateway{db: db, onboard: newOnboardRegistry()}
	// Mark the ephemeral profile so we can confirm the onboard mapping
	// is cleared on eviction. globalWG is nil in tests — that's fine,
	// the helper skips wg-go ops when it isn't running.
	g.onboard.setEphemeralProfile("10.55.0.20", "10.55.0.5", "default")

	evictEphemeralsForParent(g, "10.55.0.5")

	// hostB's ephemeral belongs to a different parent — must survive.
	if !rowExists(t, db, "hostB_eph") {
		t.Error("hostB_eph evicted; should have stayed (different parent)")
	}
	// The parent device row is never ephemeral=1; must survive.
	if !rowExists(t, db, "hostA_perm") {
		t.Error("hostA parent row deleted; eviction must not touch non-ephemeral rows")
	}
	// The onboard ephemeral-profile mapping for the evicted ephemeral
	// should be cleared so a fresh registration doesn't inherit stale
	// state.
	if got := g.onboard.ProfileForIP("10.55.0.20"); got != "" {
		t.Errorf("ProfileForIP(evicted)=%q; want empty", got)
	}
}

func rowExists(t *testing.T, db *sql.DB, pubkey string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM wg_peers WHERE pubkey = ?`, pubkey).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n > 0
}
