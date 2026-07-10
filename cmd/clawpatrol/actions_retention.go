package main

// Action-log retention. The actions table (captured request/response
// bodies + headers) is the gateway's largest by far, so without a
// retention floor it grows until the disk fills. This is the
// storage-bound analogue of startSessionSweeper: a background goroutine
// enforces a global default (gateway.actions_keep) plus per-endpoint
// overrides (endpoint `retention = "..."`).

import (
	"database/sql"
	"log"
	"strings"
	"time"
)

// actionsSweepInterval is how often the retention sweep runs. Actions
// accrue continuously, but a coarse cadence keeps the write contention
// negligible — the first tick drains any backlog, later ticks only
// clear the sliver that aged past the floor since.
const actionsSweepInterval = time.Hour

// actionsDeleteBatch bounds each DELETE so a large backlog doesn't build
// one giant transaction / WAL frame on a small-memory host.
const actionsDeleteBatch = 5000

// startActionsSweeper prunes the actions log on a fixed interval,
// enforcing per-endpoint retention with a global default.
//
// defaultKeep is the global default (gateway.actions_keep). Each
// endpoint may override it with its own `retention`. A keep of 0 (from
// "0" / "off") means keep forever: for the global default it disables
// the catch-all sweep; for an endpoint it exempts that endpoint's rows
// from pruning entirely. Per-endpoint overrides run even when the
// global default is disabled.
func (g *Gateway) startActionsSweeper(defaultKeep time.Duration) {
	if g.db == nil {
		return
	}
	go func() {
		time.Sleep(45 * time.Second) // let boot settle before the first drain
		t := time.NewTicker(actionsSweepInterval)
		defer t.Stop()
		for {
			g.sweepActions(defaultKeep)
			<-t.C
		}
	}()
}

// sweepActions runs one retention pass. Per-endpoint overrides are
// applied first (each with its own cutoff), then the global default
// sweeps everything without an explicit override — including rows whose
// endpoint is NULL/empty (internal traffic, passthrough).
func (g *Gateway) sweepActions(defaultKeep time.Duration) {
	now := time.Now()
	var overrides []string // endpoint names carrying an explicit retention

	if pol := g.Policy(); pol != nil {
		for name, ep := range pol.Endpoints {
			if strings.TrimSpace(ep.Retention) == "" {
				continue // no override → falls under the global default below
			}
			overrides = append(overrides, name)
			d := parseDurationOr(ep.Retention, 0)
			if d <= 0 {
				continue // "0" / "off" → keep this endpoint's rows forever
			}
			cutoff := now.Add(-d).UnixNano()
			if n, err := deleteActionsBatched(g.db, "endpoint = ? AND ts_ns < ?", []any{name, cutoff}); err != nil {
				log.Printf("actions: sweep endpoint %q: %v", name, err)
			} else if n > 0 {
				log.Printf("actions: pruned %d rows for endpoint %q (retention %s)", n, name, d)
			}
		}
	}

	if defaultKeep <= 0 {
		return // global default disabled; per-endpoint overrides already ran
	}
	cutoff := now.Add(-defaultKeep).UnixNano()
	where := "ts_ns < ?"
	args := []any{cutoff}
	if len(overrides) > 0 {
		// Rows for an override endpoint are handled above; exempt them
		// here. NULL/empty endpoints must still be swept, so the explicit
		// NULL check is load-bearing: `endpoint NOT IN (...)` is NULL
		// (never true) for a NULL endpoint, which would leak those rows.
		ph := strings.TrimRight(strings.Repeat("?,", len(overrides)), ",")
		where += " AND (endpoint IS NULL OR endpoint NOT IN (" + ph + "))"
		for _, n := range overrides {
			args = append(args, n)
		}
	}
	if n, err := deleteActionsBatched(g.db, where, args); err != nil {
		log.Printf("actions: sweep default: %v", err)
	} else if n > 0 {
		log.Printf("actions: pruned %d rows (default retention %s)", n, defaultKeep)
	}
}

// deleteActionsBatched deletes matching rows in bounded batches, yielding
// briefly between them so a large first-run drain doesn't starve the
// live gateway's writes on a small host. Returns the total deleted.
func deleteActionsBatched(db *sql.DB, where string, args []any) (int64, error) {
	var total int64
	for {
		batchArgs := append(append([]any{}, args...), actionsDeleteBatch)
		res, err := db.Exec(
			"DELETE FROM actions WHERE id IN (SELECT id FROM actions WHERE "+where+" LIMIT ?)",
			batchArgs...)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		if n < actionsDeleteBatch {
			return total, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
}
