package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
)

// newActionsRetentionTestGateway returns a Gateway backed by a fresh DB
// and a policy with three endpoints: "llm" keeps forever, "short" keeps
// 1h, "plain" has no override (falls under the global default).
func newActionsRetentionTestGateway(t *testing.T) *Gateway {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	g := &Gateway{db: db}
	g.policy.Store(&config.CompiledPolicy{
		Endpoints: map[string]*config.CompiledEndpoint{
			"llm":   {Name: "llm", Retention: "off"},
			"short": {Name: "short", Retention: "1h"},
			"plain": {Name: "plain"},
		},
	})
	return g
}

func insertAction(t *testing.T, g *Gateway, endpoint string, age time.Duration) {
	t.Helper()
	ts := time.Now().Add(-age).UnixNano()
	var ep any = endpoint
	if endpoint == "" {
		ep = nil // NULL endpoint (internal / passthrough traffic)
	}
	if _, err := g.db.Exec(`INSERT INTO actions (ts_ns, family, endpoint) VALUES (?,?,?)`, ts, "http", ep); err != nil {
		t.Fatalf("insert action: %v", err)
	}
}

func countActions(t *testing.T, g *Gateway, where string, args ...any) int {
	t.Helper()
	q := "SELECT count(*) FROM actions"
	if where != "" {
		q += " WHERE " + where
	}
	var n int
	if err := g.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestSweepActionsPerEndpointAndDefault(t *testing.T) {
	g := newActionsRetentionTestGateway(t)

	insertAction(t, g, "llm", 100*time.Hour) // keep-forever endpoint: both kept
	insertAction(t, g, "llm", time.Minute)
	insertAction(t, g, "short", 2*time.Hour)    // 1h retention: old dropped
	insertAction(t, g, "short", 10*time.Minute) // kept
	insertAction(t, g, "plain", 48*time.Hour)   // global default (24h): old dropped
	insertAction(t, g, "plain", time.Hour)      // kept
	insertAction(t, g, "", 48*time.Hour)        // NULL endpoint: swept by default
	insertAction(t, g, "", time.Hour)           // kept

	g.sweepActions(24 * time.Hour)

	if got := countActions(t, g, "endpoint = 'llm'"); got != 2 {
		t.Errorf("llm rows = %d, want 2 (retention off keeps all ages)", got)
	}
	if got := countActions(t, g, "endpoint = 'short'"); got != 1 {
		t.Errorf("short rows = %d, want 1 (1h override drops the 2h-old row)", got)
	}
	if got := countActions(t, g, "endpoint = 'plain'"); got != 1 {
		t.Errorf("plain rows = %d, want 1 (24h default drops the 48h-old row)", got)
	}
	if got := countActions(t, g, "endpoint IS NULL"); got != 1 {
		t.Errorf("null-endpoint rows = %d, want 1 (default sweeps endpointless rows)", got)
	}
	if got := countActions(t, g, ""); got != 5 {
		t.Errorf("total rows = %d, want 5", got)
	}
}

// With the global default disabled ("0"/"off" → 0), per-endpoint
// overrides still run, but everything else is kept.
func TestSweepActionsGlobalDisabledKeepsPerEndpointOverrides(t *testing.T) {
	g := newActionsRetentionTestGateway(t)

	insertAction(t, g, "short", 2*time.Hour) // 1h override: dropped even with default off
	insertAction(t, g, "plain", 9000*time.Hour)
	insertAction(t, g, "", 9000*time.Hour)

	g.sweepActions(0)

	if got := countActions(t, g, "endpoint = 'short'"); got != 0 {
		t.Errorf("short rows = %d, want 0 (per-endpoint override runs even with default off)", got)
	}
	if got := countActions(t, g, "endpoint = 'plain'"); got != 1 {
		t.Errorf("plain rows = %d, want 1 (default off keeps everything without an override)", got)
	}
	if got := countActions(t, g, "endpoint IS NULL"); got != 1 {
		t.Errorf("null-endpoint rows = %d, want 1 (default off keeps endpointless rows)", got)
	}
}

// A malformed per-endpoint retention (e.g. a missing unit) or a
// negative one must fall back to the global default sweep — not
// silently keep the endpoint's rows forever (defeats the point on a
// typo), and not treat the cutoff as being in the future (a negative
// duration would otherwise delete the endpoint's entire history).
func TestSweepActionsInvalidRetentionFallsBackToDefault(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	g := &Gateway{db: db}
	g.policy.Store(&config.CompiledPolicy{
		Endpoints: map[string]*config.CompiledEndpoint{
			"typo": {Name: "typo", Retention: "30"},  // missing unit → invalid
			"neg":  {Name: "neg", Retention: "-24h"}, // negative → invalid
		},
	})

	insertAction(t, g, "typo", 48*time.Hour) // older than the default → must be pruned
	insertAction(t, g, "typo", time.Hour)    // within the default → kept
	insertAction(t, g, "neg", 48*time.Hour)  // older than the default → must be pruned
	insertAction(t, g, "neg", time.Hour)     // within the default → MUST survive a negative retention

	g.sweepActions(24 * time.Hour)

	if got := countActions(t, g, "endpoint = 'typo'"); got != 1 {
		t.Errorf("typo-retention rows = %d, want 1 (invalid retention must fall back to the default sweep)", got)
	}
	if got := countActions(t, g, "endpoint = 'neg'"); got != 1 {
		t.Errorf("negative-retention rows = %d, want 1 (negative retention must fall back to the default sweep, not wipe the endpoint)", got)
	}
}

// A zero-valued duration ("0s", "0h") is the "0" sentinel spelled
// differently and must mean keep-forever. Before the d == 0 guard it
// fell through to the delete with cutoff = now, wiping the endpoint's
// entire history — the exact inverse of what the operator asked for.
func TestSweepActionsZeroDurationRetentionIsExempt(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	g := &Gateway{db: db}
	g.policy.Store(&config.CompiledPolicy{
		Endpoints: map[string]*config.CompiledEndpoint{
			"zero": {Name: "zero", Retention: "0s"},
		},
	})

	insertAction(t, g, "zero", 9000*time.Hour) // far past the default → still kept
	insertAction(t, g, "zero", time.Minute)

	g.sweepActions(24 * time.Hour)

	if got := countActions(t, g, "endpoint = 'zero'"); got != 2 {
		t.Errorf("zero-retention rows = %d, want 2 (\"0s\" must mean keep forever, same as \"0\")", got)
	}
}

// The batched delete must drain a backlog larger than one batch.
func TestDeleteActionsBatchedDrainsBacklog(t *testing.T) {
	g := newActionsRetentionTestGateway(t)
	for i := 0; i < actionsDeleteBatch+250; i++ {
		insertAction(t, g, "plain", 48*time.Hour)
	}
	n, err := deleteActionsBatched(g.db, "ts_ns < ?", []any{time.Now().UnixNano()})
	if err != nil {
		t.Fatalf("deleteActionsBatched: %v", err)
	}
	if n != int64(actionsDeleteBatch+250) {
		t.Errorf("deleted = %d, want %d", n, actionsDeleteBatch+250)
	}
	if got := countActions(t, g, ""); got != 0 {
		t.Errorf("remaining = %d, want 0", got)
	}
}
