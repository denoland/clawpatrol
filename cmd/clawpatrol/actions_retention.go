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
// "0" / "off", or any zero-valued duration like "0s") means keep
// forever: for the global default it disables the catch-all sweep; for
// an endpoint it exempts that endpoint's rows from pruning entirely.
// Per-endpoint overrides run even when the global default is disabled.
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
			raw := strings.TrimSpace(ep.Retention)
			switch raw {
			case "":
				continue // no override → falls under the global default below
			case "0", "off":
				overrides = append(overrides, name) // exempt: keep this endpoint's rows forever
				continue
			}
			d, err := time.ParseDuration(raw)
			if err != nil || d < 0 {
				// A malformed (or negative) retention must NOT silently
				// mean "keep forever" — that's the disk-growth direction
				// this whole feature exists to prevent. Leave it out of
				// overrides so the global default still prunes the
				// endpoint, and log loudly. Config load rejects these too;
				// this guard covers policies swapped in through any path
				// that skipped that validation.
				if err == nil {
					log.Printf("actions: endpoint %q has a negative retention %q — applying the default sweep instead", name, raw)
				} else {
					log.Printf("actions: endpoint %q has an invalid retention %q: %v — applying the default sweep instead", name, raw, err)
				}
				continue
			}
			if d == 0 {
				// Zero-valued durations ("0s", "0h", …) carry the same
				// intent as the "0" / "off" sentinels: keep forever. They
				// must NOT fall through to the delete below, where
				// cutoff = now would wipe the endpoint's entire history —
				// the exact inverse of what the operator asked for.
				overrides = append(overrides, name)
				continue
			}
			overrides = append(overrides, name)
			cutoff := now.Add(-d).UnixNano()
			if n, derr := deleteActionsBatched(g.db, "endpoint = ? AND ts_ns < ?", []any{name, cutoff}); derr != nil {
				log.Printf("actions: sweep endpoint %q: %v", name, derr)
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
