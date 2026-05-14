package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/denoland/clawpatrol/config"
)

// Update-checker / telemetry. Contract: doc/telemetry.md.
//
// One goroutine, started from runGateway. Pings clawpatrol.dev once
// after a 30 s grace period and every 6 h thereafter. The grace
// period stops short-lived `--help` / config-validation runs from
// counting as installs.
//
// Three opt-out paths, any of which silences the goroutine entirely:
//   - HCL: telemetry = false in gateway.hcl
//   - env: CLAWPATROL_TELEMETRY=0
//   - env: DO_NOT_TRACK=1 (de-facto OSS standard)
//
// Hard contract: a failing telemetry call must not affect the
// gateway. Every public entry point recovers panics; errors are
// logged at most once per failure type and otherwise swallowed.

const (
	telemetryEndpoint = "https://clawpatrol.dev/api/telemetry/v1/check"
	telemetryInterval = 6 * time.Hour
	telemetryGrace    = 30 * time.Second
	telemetryTimeout  = 5 * time.Second
)

// Build-time identity. Set via -ldflags at release; "dev" for local
// builds so the server can tell development pings apart from real
// installs.
var (
	buildVersion = "dev"
	buildGitSHA  = ""
)

var processStart = time.Now()

// updateBanner is read by the dashboard via /api/state. nil when no
// upgrade is available.
type updateBanner struct {
	Latest          string `json:"latest"`
	UpdateAvailable bool   `json:"update_available"`
	URL             string `json:"url"`
	Advisory        string `json:"advisory,omitempty"`
}

var currentUpdateBanner atomic.Pointer[updateBanner]

func telemetryEnabled(cfg *config.Gateway) bool {
	if os.Getenv("DO_NOT_TRACK") == "1" {
		return false
	}
	if v := os.Getenv("CLAWPATROL_TELEMETRY"); v == "0" {
		return false
	}
	if cfg != nil && cfg.Telemetry != nil && !*cfg.Telemetry {
		return false
	}
	return true
}

func startTelemetry(g *Gateway) {
	if !telemetryEnabled(g.cfg) {
		log.Printf("telemetry: disabled")
		return
	}
	id, err := loadOrCreateInstanceID(g.db)
	if err != nil {
		log.Printf("telemetry: %v; disabled", err)
		return
	}
	log.Printf(
		"telemetry: on (instance %s, every %s). "+
			"opt out: telemetry = false in gateway.hcl, "+
			"CLAWPATROL_TELEMETRY=0, or DO_NOT_TRACK=1",
		shortID(id), telemetryInterval,
	)
	go telemetryLoop(g, id)
}

func telemetryLoop(g *Gateway, instanceID string) {
	defer recoverAndLog("telemetryLoop")
	time.Sleep(telemetryGrace)
	telemetrySendOnce(g, instanceID)
	t := time.NewTicker(telemetryInterval)
	defer t.Stop()
	for range t.C {
		telemetrySendOnce(g, instanceID)
	}
}

func telemetrySendOnce(g *Gateway, instanceID string) {
	defer recoverAndLog("telemetrySendOnce")
	body, err := buildTelemetryPayload(g, instanceID)
	if err != nil {
		log.Printf("telemetry: build payload: %v", err)
		return
	}
	resp, err := postTelemetry(body)
	if err != nil {
		// Network errors are common (offline gateways, bad DNS,
		// etc.). Don't spam the log on every cycle.
		return
	}
	if resp == nil {
		return
	}
	applyTelemetryResponse(resp)
}

func applyTelemetryResponse(r *telemetryResp) {
	if !r.UpdateAvailable {
		currentUpdateBanner.Store(nil)
		return
	}
	prev := currentUpdateBanner.Load()
	b := &updateBanner{
		Latest: r.Latest, UpdateAvailable: true, URL: r.URL,
	}
	if r.Advisory != nil {
		b.Advisory = r.Advisory.Message
	}
	currentUpdateBanner.Store(b)
	if prev == nil || prev.Latest != b.Latest {
		log.Printf(
			"clawpatrol %s available; you're on %s. see %s",
			r.Latest, buildVersion, r.URL,
		)
	}
}

func postTelemetry(payload []byte) (*telemetryResp, error) {
	ctx, cancel := context.WithTimeout(
		context.Background(), telemetryTimeout,
	)
	defer cancel()
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, telemetryEndpoint,
		bytes.NewReader(payload),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "clawpatrol/"+buildVersion)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"telemetry: server status %d", resp.StatusCode,
		)
	}
	var out telemetryResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).
		Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

type telemetryReq struct {
	InstanceID         string `json:"instance_id"`
	Version            string `json:"version"`
	GitSHA             string `json:"git_sha,omitempty"`
	OS                 string `json:"os"`
	Arch               string `json:"arch"`
	GoVersion          string `json:"go_version"`
	UptimeS            int64  `json:"uptime_s"`
	ConnectedDevices1h int64  `json:"connected_devices_1h"`
	ActionsCount1h     int64  `json:"actions_count_1h"`
	BytesIn1h          int64  `json:"bytes_in_1h"`
	BytesOut1h         int64  `json:"bytes_out_1h"`
	Transport          string `json:"transport"`
}

type telemetryResp struct {
	Latest          string `json:"latest"`
	YourVersion     string `json:"your_version"`
	UpdateAvailable bool   `json:"update_available"`
	URL             string `json:"url"`
	Advisory        *struct {
		Level   string `json:"level"`
		Message string `json:"message"`
	} `json:"advisory"`
}

func buildTelemetryPayload(
	g *Gateway, instanceID string,
) ([]byte, error) {
	devices := connectedDevicesIn1h(g)
	actions, bin, bout := actionsCountIn1h(g)
	transport := "tailscale"
	if g.cfg != nil && strings.EqualFold(g.cfg.Control, "wireguard") {
		transport = "wireguard"
	}
	r := telemetryReq{
		InstanceID:         instanceID,
		Version:            buildVersion,
		GitSHA:             buildGitSHA,
		OS:                 runtime.GOOS,
		Arch:               runtime.GOARCH,
		GoVersion:          runtime.Version(),
		UptimeS:            int64(time.Since(processStart).Seconds()),
		ConnectedDevices1h: devices,
		ActionsCount1h:     actions,
		BytesIn1h:          bin,
		BytesOut1h:         bout,
		Transport:          transport,
	}
	return json.Marshal(r)
}

func connectedDevicesIn1h(g *Gateway) int64 {
	defer recoverAndLog("connectedDevicesIn1h")
	if g == nil || g.agents == nil {
		return 0
	}
	cutoff := time.Now().Add(-time.Hour)
	var n int64
	for _, a := range g.agents.snapshot() {
		if a.LastAt.After(cutoff) {
			n++
		}
	}
	return n
}

func actionsCountIn1h(g *Gateway) (int64, int64, int64) {
	defer recoverAndLog("actionsCountIn1h")
	if g == nil || g.db == nil {
		return 0, 0, 0
	}
	cutoff := time.Now().Add(-time.Hour).UnixNano()
	var (
		count    sql.NullInt64
		bytesIn  sql.NullInt64
		bytesOut sql.NullInt64
	)
	err := g.db.QueryRow(
		`SELECT COUNT(*),
		        COALESCE(SUM(bytes_in), 0),
		        COALESCE(SUM(bytes_out), 0)
		 FROM actions WHERE ts_ns > ?`, cutoff,
	).Scan(&count, &bytesIn, &bytesOut)
	if err != nil {
		return 0, 0, 0
	}
	return count.Int64, bytesIn.Int64, bytesOut.Int64
}

func loadOrCreateInstanceID(db *sql.DB) (string, error) {
	if db == nil {
		return "", fmt.Errorf("instance_id: no db")
	}
	var id string
	err := db.QueryRow(`SELECT instance_id FROM telemetry_state WHERE id = 1`).Scan(&id)
	if err == nil {
		id = strings.TrimSpace(id)
		if id != "" {
			return id, nil
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("read instance_id: %w", err)
	}
	id = newReqID() // UUIDv7
	if _, err := db.Exec(
		`INSERT INTO telemetry_state (id, instance_id, created_ns) VALUES (1, ?, ?)`,
		id, time.Now().UnixNano(),
	); err != nil {
		// Non-fatal: emit the ID this run, accept that the next
		// restart will mint a new one and over-count by one.
		log.Printf(
			"telemetry: persist instance_id: %v "+
				"(every restart will count as fresh)", err,
		)
	}
	return id, nil
}

func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// recoverAndLog turns a panic into a log line. Used at every entry
// point so a bug in the telemetry path can never bring down the
// gateway process.
func recoverAndLog(where string) {
	if r := recover(); r != nil {
		log.Printf("telemetry: panic in %s: %v\n%s",
			where, r, debug.Stack())
	}
}
