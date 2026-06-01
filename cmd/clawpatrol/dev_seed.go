//go:build dev

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// devSeedHook bundles the -dev-seed / -dev-seed-live flags so main.go
// can wire them through a single attach + run pair without referring
// to any dev-specific types directly. Default (non-dev) builds pick
// up the no-op variant in dev_seed_off.go and ship no seeder code at
// all.
type devSeedHook struct {
	bulk *int
	live *bool
}

func devSeedAttach(fs *flag.FlagSet) devSeedHook {
	return devSeedHook{
		bulk: fs.Int("dev-seed", 0,
			"wipe + populate the DB with N synthetic actions (refuses if a root password is set)"),
		live: fs.Bool("dev-seed-live", false,
			"emit a synthetic action every 200–2000 ms (refuses if a root password is set)"),
	}
}

func (h devSeedHook) Run(ctx context.Context, g *Gateway) {
	if h.bulk != nil && *h.bulk > 0 {
		if err := devSeed(g, *h.bulk); err != nil {
			log.Fatalf("dev-seed: %v", err)
		}
	}
	if h.live != nil && *h.live {
		go devSeedLive(ctx, g)
	}
}

// devSinkReloadRecent re-warms the sink's recent-events ring from the
// DB. The bulk seed path writes directly into the actions table so
// 50k rows don't overflow Sink's 4096-event channel — but that also
// means the ring (which only grows via Emit) misses them and
// /api/events backlogs would start empty. This function reaches into
// the same private fields NewSink touches at boot to refresh the
// ring. Lives in the dev_seed.go (//go:build dev) file so the default
// prod build ships no caller and no body.
func devSinkReloadRecent(s *Sink) {
	if s == nil || s.db == nil {
		return
	}
	seed, err := readTailEvents(s.db, s.recentCap)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.recent {
		s.recent[i] = Event{}
	}
	n := len(seed)
	if n > s.recentCap {
		seed = seed[n-s.recentCap:]
		n = s.recentCap
	}
	copy(s.recent, seed)
	s.recentLen = n
	s.recentNext = n % s.recentCap
}

// Dev-only seeder. Populates the gateway DB and in-memory registries
// with a plausible spread of synthetic devices, sessions, credentials,
// actions, and HITL pending items so the dashboard has data to style
// against without standing up real wg / agent traffic.
//
// Gated on "no root password set yet": dev-seed wipes the actions /
// devices / sessions tables, so we refuse if a real operator has
// initialized the dashboard. Together with the `-tags dev` build
// constraint that's two layers of opt-in.

const devSeedKnownEndpointGithubAPI = "github-api"

func devSeed(g *Gateway, count int) error {
	if _, rootSet, err := lookupDashboardUser(g.db, dashboardRootUsername); err != nil {
		return fmt.Errorf("lookup root: %w", err)
	} else if rootSet {
		return fmt.Errorf("dev-seed refuses to run: a dashboard root password is set; this looks like a real install")
	}
	r := rand.New(rand.NewSource(42))
	log.Printf("dev-seed: wiping data tables and inserting %d actions", count)
	if err := devSeedWipe(g); err != nil {
		return fmt.Errorf("wipe: %w", err)
	}
	devices, err := devSeedDevices(g, r, 24)
	if err != nil {
		return fmt.Errorf("devices: %w", err)
	}
	if err := devSeedCredentials(g.db); err != nil {
		return fmt.Errorf("credentials: %w", err)
	}
	if err := devSeedSessions(g, r, devices, 60); err != nil {
		return fmt.Errorf("sessions: %w", err)
	}
	if err := devSeedActions(g, r, devices, count); err != nil {
		return fmt.Errorf("actions: %w", err)
	}
	devSeedRefreshRegistries(g, devices)
	devSinkReloadRecent(g.sink)
	devSeedHITL(g, r, devices, 12)
	log.Printf("dev-seed: complete (%d devices, %d actions)", len(devices), count)
	return nil
}

// devSeedLive emits one synthetic action every 200–2000 ms and posts a
// fresh HITL pending item every ~30 s. Caps the HITL list at
// liveHITLCap by discarding the oldest synthetic entry. Returns when
// ctx is cancelled.
func devSeedLive(ctx context.Context, g *Gateway) {
	if _, rootSet, err := lookupDashboardUser(g.db, dashboardRootUsername); err != nil {
		log.Printf("dev-seed: live mode skipped (lookup root: %v)", err)
		return
	} else if rootSet {
		log.Printf("dev-seed: live mode skipped (dashboard root password is set; looks like a real install)")
		return
	}
	devices := devSeedLoadDeviceList(g.db)
	if len(devices) == 0 {
		log.Printf("dev-seed: live mode skipped (no seeded devices found)")
		return
	}
	log.Printf("dev-seed: live mode on — ticking every 200–2000 ms")
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	hitlTicker := time.NewTicker(30 * time.Second)
	defer hitlTicker.Stop()
	tracker := newLiveHITLTracker(g, 20)
	// One reusable timer Reset each iteration. Go 1.23+ Stop/Reset no
	// longer leak stale channel fires, so the non-timer select branches
	// just Stop and the next iteration Resets cleanly.
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		gap := 200 + r.Intn(1801)
		timer.Reset(time.Duration(gap) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-hitlTicker.C:
			timer.Stop()
			tracker.add(r, devices)
		case <-timer.C:
			g.sink.Emit(devSeedAction(r, devices, time.Now()))
		}
	}
}

// liveHITLTracker keeps a bounded FIFO of HITL IDs the live loop has
// added so the pending list doesn't grow unbounded across hours of
// styling work. When the cap is reached, the oldest entry is
// Discard'd before the new one lands.
type liveHITLTracker struct {
	g   *Gateway
	mu  sync.Mutex
	ids []string
	cap int
}

func newLiveHITLTracker(g *Gateway, cap int) *liveHITLTracker {
	return &liveHITLTracker{g: g, cap: cap}
}

func (t *liveHITLTracker) add(r *rand.Rand, devices []devSeedDevice) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.ids) >= t.cap {
		oldest := t.ids[0]
		t.ids = t.ids[1:]
		t.g.hitl.Discard(oldest)
	}
	id := devSeedAddHITL(t.g, r, devices, 1)
	if id != "" {
		t.ids = append(t.ids, id)
	}
}

type devSeedDevice struct {
	ip       string
	name     string
	profile  string
	extV4    string
	extV6    string
	blocked  bool
	created  time.Time
	lastSeen time.Time
}

var devSeedHostnames = []string{
	"macbook-jane", "macbook-alex", "macbook-priya", "macbook-sam",
	"ubuntu-dev-1", "ubuntu-dev-2", "fedora-build", "debian-staging",
	"ci-runner-1", "ci-runner-2", "ci-runner-3", "ci-runner-4",
	"demo-vm-east", "demo-vm-west", "load-test-7",
	"alex-laptop", "kira-mac", "max-thinkpad",
	"deploy-bot", "snyk-bot", "renovate-bot",
	"build-host-east", "build-host-west", "scratch-vm",
}

var devSeedProfiles = []string{
	"default", "default", "default",
	"ops-team", "ops-team",
	"data-team",
	"support",
	"ci-bot",
}

func devSeedDevices(g *Gateway, r *rand.Rand, n int) ([]devSeedDevice, error) {
	out := make([]devSeedDevice, 0, n)
	now := time.Now()
	for i := 0; i < n; i++ {
		d := devSeedDevice{
			ip:       fmt.Sprintf("10.55.0.%d", 7+i),
			name:     devSeedHostnames[i%len(devSeedHostnames)],
			profile:  devSeedProfiles[r.Intn(len(devSeedProfiles))],
			extV4:    fmt.Sprintf("203.0.113.%d", 1+r.Intn(254)),
			created:  now.Add(-time.Duration(r.Intn(60*24)) * time.Hour),
			lastSeen: now.Add(-time.Duration(r.Intn(48*60)) * time.Minute),
			blocked:  r.Intn(10) == 0,
		}
		if r.Intn(3) == 0 {
			d.extV6 = fmt.Sprintf("2001:db8:%x::%x", r.Intn(0xffff), r.Intn(0xffff))
		}
		out = append(out, d)
	}
	tx, err := g.db.Begin()
	if err != nil {
		return nil, err
	}
	for _, d := range out {
		blocked := 0
		if d.blocked {
			blocked = 1
		}
		if _, err := tx.Exec(`
			INSERT INTO devices
			  (id, name, profile, blocked, created_ns, last_seen_ns, external_ipv4, external_ipv6)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			d.ip, d.name, d.profile, blocked,
			d.created.UnixNano(), d.lastSeen.UnixNano(),
			d.extV4, nullIfEmpty(d.extV6)); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
	}
	return out, tx.Commit()
}

func devSeedCredentials(db *sql.DB) error {
	now := time.Now().UnixNano()
	// Credentials are global (one row per id, no per-profile fan-out).
	// The display_name + avatar attached to a credential is the
	// connected-as identity surfaced anywhere that credential is
	// referenced.
	creds := []struct {
		id, display, avatar string
	}{
		// Original bearer-token quartet
		{"anthropic-tok", "Jane Doe", "https://i.pravatar.cc/64?img=12"},
		{"github-tok", "octo-engineering", "https://avatars.githubusercontent.com/u/9919?s=64"},
		{"openai-tok", "", ""},
		{"slack-tok", "agent-ops", "https://i.pravatar.cc/64?img=33"},

		// Brand-typed credentials so the dashboard renders proper logos
		{"claude", "jane@example.com", "https://i.pravatar.cc/64?img=15"},
		{"codex", "alex@example.com", "https://i.pravatar.cc/64?img=18"},
		{"github", "octocat", "https://avatars.githubusercontent.com/u/583231?s=64"},
		{"notion", "Engineering", ""},
		{"gemini", "data@example.com", "https://i.pravatar.cc/64?img=27"},
		{"slack-bot", "claw-patrol-bot", ""},
		{"pg-writer", "writer", ""},
		{"pg-readonly", "readonly", ""},
		{"ch-analytics", "analytics", ""},
		{"alerts-tg", "alerts-bot", ""},
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, c := range creds {
		if _, err := tx.Exec(`
			INSERT INTO credentials
			  (id, access_token, token_type, refresh_token,
			   expiry_ns, updated_ns, display_name, avatar_url)
			VALUES (?, 'redacted-fake-token', 'Bearer', '', 0, ?, ?, ?)`,
			c.id, now,
			nullIfEmpty(c.display), nullIfEmpty(c.avatar)); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	bearers := []struct {
		credential, slot, value string
	}{
		{"anthropic-tok", "", "sk-ant-fake-redacted"},
		{"github-tok", "", "ghp_fake_redacted"},
		{"slack-tok", "bot", "xoxb-fake-redacted"},
		{"slack-tok", "signing", "fake-signing-secret"},
		{"gemini", "", "AIza-fake-redacted"},
		{"alerts-tg", "", "1234567890:fake-tg-redacted"},
	}
	for _, b := range bearers {
		if _, err := tx.Exec(`
			INSERT INTO credential_secrets (credential, slot, value, updated_ns)
			VALUES (?, ?, ?, ?)`,
			b.credential, b.slot, b.value, now); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

var devSeedSessionTitles = []string{
	"fix auth middleware bug",
	"refactor HCL editor highlighting",
	"investigate flaky integration test",
	"review PR #234 — credentials API",
	"port migration runner to libsql",
	"add OpenTelemetry export to gateway",
	"draft launch blog post",
	"benchmark sqlite vs duckdb for actions",
	"implement Slack approver flow",
	"chase down 502 from k8s API",
	"write dashboard onboarding tour",
	"audit secret-injection paths",
	"clean up agents.go session sweeper",
	"build the live-requests pagination",
	"land webhook deduplication",
}

var (
	devSeedClaudeModels = []string{"claude-opus-4-7", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"}
	devSeedOpenAIModels = []string{"gpt-5", "gpt-5-mini", "o3", "gpt-4.1"}
	devSeedCodexModels  = []string{"gpt-5-codex", "gpt-5-codex-mini"}
)

func devSeedSessions(g *Gateway, r *rand.Rand, devices []devSeedDevice, n int) error {
	tx, err := g.db.Begin()
	if err != nil {
		return err
	}
	now := time.Now()
	for i := 0; i < n; i++ {
		d := devices[r.Intn(len(devices))]
		var typ, model string
		var ctxMax int64
		switch r.Intn(10) {
		case 0, 1, 2, 3, 4:
			typ, ctxMax = "claude_usage", 200000
			model = devSeedClaudeModels[r.Intn(len(devSeedClaudeModels))]
		case 5, 6, 7:
			typ, ctxMax = "openai_usage", 128000
			model = devSeedOpenAIModels[r.Intn(len(devSeedOpenAIModels))]
		default:
			typ, ctxMax = "codex_ws_usage", 200000
			model = devSeedCodexModels[r.Intn(len(devSeedCodexModels))]
		}
		title := devSeedSessionTitles[r.Intn(len(devSeedSessionTitles))]
		idHash := sha256.Sum256(fmt.Appendf(nil, "%d|%s|%s|%d", i, d.ip, title, r.Int()))
		id := hex.EncodeToString(idHash[:])[:16]
		firstAt := now.Add(-time.Duration(r.Intn(14*24*60)) * time.Minute)
		span := int(now.Sub(firstAt).Minutes())
		if span < 1 {
			span = 1
		}
		lastAt := firstAt.Add(time.Duration(r.Intn(span)) * time.Minute)
		ctxUsed := int64(r.Intn(int(ctxMax)))
		tokensIn := int64(2000 + r.Intn(50000))
		tokensOut := int64(500 + r.Intn(20000))
		reqs := int64(5 + r.Intn(500))
		if _, err := tx.Exec(`
			INSERT INTO sessions
			  (agent_ip, type, id, title, model,
			   tokens_in, tokens_out, ctx_used, ctx_max, reqs,
			   first_at, last_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			d.ip, typ, id, title, model,
			tokensIn, tokensOut, ctxUsed, ctxMax, reqs,
			firstAt.UnixNano(), lastAt.UnixNano()); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

type devSeedEndpoint struct {
	endpoint, rule, host string
	paths, methods       []string
	family               string
}

var devSeedEndpoints = []devSeedEndpoint{
	{"anthropic", "anthropic-allow", "api.anthropic.com",
		[]string{"/v1/messages", "/v1/models"},
		[]string{"POST", "POST", "POST", "GET"}, "https"},
	{"openai", "openai-allow", "api.openai.com",
		[]string{"/v1/chat/completions", "/v1/responses", "/v1/embeddings", "/v1/models"},
		[]string{"POST", "POST", "POST", "POST", "GET"}, "https"},
	{devSeedKnownEndpointGithubAPI, "github-reads", "api.github.com",
		[]string{"/repos/denoland/clawpatrol/issues", "/repos/denoland/clawpatrol/pulls", "/user", "/repos/denoland/clawpatrol/commits/main"},
		[]string{"GET", "GET", "GET", "HEAD"}, "https"},
	{devSeedKnownEndpointGithubAPI, "github-writes", "api.github.com",
		[]string{"/repos/denoland/clawpatrol/issues", "/repos/denoland/clawpatrol/pulls/240/comments", "/repos/denoland/clawpatrol/issues/238/labels"},
		[]string{"POST", "PATCH", "PUT", "DELETE"}, "https"},
	{"slack", "slack-allow", "hooks.slack.com",
		[]string{"/services/T0/B0/abc"},
		[]string{"POST"}, "https"},
	// Passthrough (unknown host) — exercises rule="" rendering.
	{"", "", "registry.npmjs.org",
		[]string{"/preact", "/react", "/@types%2Fnode"},
		[]string{"GET"}, "https"},
}

func devSeedPickEndpoint(r *rand.Rand) devSeedEndpoint {
	switch n := r.Intn(100); {
	case n < 35:
		return devSeedEndpoints[0]
	case n < 50:
		return devSeedEndpoints[1]
	case n < 75:
		return devSeedEndpoints[2]
	case n < 85:
		return devSeedEndpoints[3]
	case n < 90:
		return devSeedEndpoints[4]
	default:
		return devSeedEndpoints[5]
	}
}

func devSeedAction(r *rand.Rand, devices []devSeedDevice, ts time.Time) Event {
	d := devices[r.Intn(len(devices))]
	ep := devSeedPickEndpoint(r)
	method := ep.methods[r.Intn(len(ep.methods))]
	path := ep.paths[r.Intn(len(ep.paths))]
	status, verdict, reason := devSeedStatus(r, ep)
	ev := Event{
		Ts:       ts,
		ID:       devSeedID(r),
		Mode:     "mitm",
		AgentIP:  d.ip,
		Host:     ep.host,
		Method:   method,
		Path:     path,
		Status:   status,
		In:       int64(50 + r.Intn(10000)),
		Out:      int64(50 + r.Intn(50000)),
		Ms:       devSeedLatency(r),
		Action:   verdict,
		Reason:   reason,
		Endpoint: ep.endpoint,
		Rule:     ep.rule,
		Family:   ep.family,
		Facets:   map[string]any{"method": method, "path": path},
	}
	if r.Intn(20) == 0 {
		ev.ReqSha = devSeedHex(r, 32)
		ev.RespSha = devSeedHex(r, 32)
		ev.ReqBody = fmt.Sprintf(`{"model":"%s","messages":[{"role":"user","content":"%s"}]}`,
			devSeedClaudeModels[r.Intn(len(devSeedClaudeModels))],
			devSeedSessionTitles[r.Intn(len(devSeedSessionTitles))])
		ev.RespBody = `{"id":"msg_abc123","type":"message","role":"assistant","content":[{"type":"text","text":"Sure — let me think about that..."}],"stop_reason":"end_turn"}`
		ev.ReqHeaders = map[string]string{
			"Content-Type":  "application/json",
			"User-Agent":    "clawpatrol/0.1 anthropic-sdk/0.55",
			"Authorization": "***",
		}
		ev.RespHeaders = map[string]string{
			"Content-Type":      "application/json",
			"x-ratelimit-input": "180000",
		}
	}
	return ev
}

func devSeedStatus(r *rand.Rand, ep devSeedEndpoint) (int, string, string) {
	if ep.rule == "github-writes" {
		switch n := r.Intn(100); {
		case n < 75:
			return 200, "approved", "approved by ops"
		case n < 90:
			return 403, "denied", "denied by ops"
		default:
			return 408, "denied", "timeout"
		}
	}
	switch n := r.Intn(100); {
	case n < 80:
		return 200, "allow", ""
	case n < 85:
		return 204, "allow", ""
	case n < 89:
		return 401, "allow", "upstream auth"
	case n < 92:
		return 404, "allow", ""
	case n < 95:
		return 429, "allow", "rate limit"
	case n < 97:
		return 500, "error", "upstream 500"
	case n < 99:
		return 502, "error", "upstream 502"
	default:
		return 403, "deny", "policy: deny by default"
	}
}

func devSeedLatency(r *rand.Rand) int64 {
	base := 80 + r.Intn(720)
	if r.Intn(50) == 0 {
		base += 4000 + r.Intn(6000)
	}
	return int64(base)
}

// devSeedActions inserts count rows directly via SQL. Sink.Emit would
// drop most through its 4096-event channel; for bulk backfill we go
// straight to the table the sink would have written to.
func devSeedActions(g *Gateway, r *rand.Rand, devices []devSeedDevice, count int) error {
	const batch = 1000
	now := time.Now()
	for offset := 0; offset < count; offset += batch {
		end := offset + batch
		if end > count {
			end = count
		}
		tx, err := g.db.Begin()
		if err != nil {
			return err
		}
		for i := offset; i < end; i++ {
			// log-decay age over 14d: r²·14d → most rows within last 24h.
			ageMin := int(float64(14*24*60) * r.Float64() * r.Float64())
			ev := devSeedAction(r, devices, now.Add(-time.Duration(ageMin)*time.Minute))
			rqhJSON, _ := json.Marshal(ev.ReqHeaders)
			rshJSON, _ := json.Marshal(ev.RespHeaders)
			extraJSON, _ := json.Marshal(ev.Facets)
			if _, err := tx.Exec(`
				INSERT INTO actions
				  (action_id, ts_ns, mode, family, agent_ip, host,
				   method, path, status, bytes_in, bytes_out,
				   ms, action, reason, req_sha, resp_sha,
				   req_body, resp_body,
				   req_headers, resp_headers, extra,
				   endpoint, rule)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				ev.ID, ev.Ts.UnixNano(), ev.Mode, ev.Family, ev.AgentIP,
				ev.Host, ev.Method, ev.Path, ev.Status,
				ev.In, ev.Out, ev.Ms, ev.Action, ev.Reason,
				ev.ReqSha, ev.RespSha,
				ev.ReqBody, ev.RespBody,
				devSeedHeadersJSON(rqhJSON), devSeedHeadersJSON(rshJSON),
				string(extraJSON),
				ev.Endpoint, ev.Rule,
			); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// json.Marshal of a nil map returns "null"; the sink stores "" in that
// case (see web.go drain). Mirror that so the columns match what real
// traffic produces.
func devSeedHeadersJSON(b []byte) string {
	if len(b) == 0 || string(b) == "null" {
		return ""
	}
	return string(b)
}

var devSeedHITLPrompts = []struct {
	endpoint, host, method, path, ua, reason, body string
}{
	{devSeedKnownEndpointGithubAPI, "api.github.com", "POST",
		"/repos/denoland/clawpatrol/issues",
		"clawpatrol/0.1 github-cli/2.61",
		"github-writes: human approval required",
		`{"title":"clean up stale onboard rows","body":"Sweep onboard requests older than 24h..."}`},
	{devSeedKnownEndpointGithubAPI, "api.github.com", "PATCH",
		"/repos/denoland/clawpatrol/pulls/240",
		"clawpatrol/0.1 github-cli/2.61",
		"github-writes: human approval required",
		`{"state":"closed"}`},
	{devSeedKnownEndpointGithubAPI, "api.github.com", "DELETE",
		"/repos/denoland/clawpatrol/issues/238/labels/bug",
		"clawpatrol/0.1 github-cli/2.61",
		"github-writes: human approval required",
		``},
	{"slack", "hooks.slack.com", "POST",
		"/services/T0/B0/abc",
		"clawpatrol/0.1 slack-sdk-go/1.4",
		"slack: outbound webhook to public channel",
		`{"text":"@here gateway proxy hit 5xx on 3 endpoints in the last 5m"}`},
	{"openai", "api.openai.com", "POST",
		"/v1/chat/completions",
		"clawpatrol/0.1 openai-python/2.1",
		"openai: large prompt over policy size limit",
		`{"model":"gpt-5","messages":[...20000 tokens elided...]}`},
}

func devSeedHITL(g *Gateway, r *rand.Rand, devices []devSeedDevice, n int) {
	for i := 0; i < n; i++ {
		devSeedAddHITL(g, r, devices, 1)
	}
}

func devSeedAddHITL(g *Gateway, r *rand.Rand, devices []devSeedDevice, n int) string {
	if g.hitl == nil || len(devices) == 0 {
		return ""
	}
	var last string
	for i := 0; i < n; i++ {
		p := devSeedHITLPrompts[r.Intn(len(devSeedHITLPrompts))]
		d := devices[r.Intn(len(devices))]
		id, _ := g.hitl.Add(runtime.HITLPending{
			AgentIP:    d.ip,
			Host:       p.host,
			Method:     p.method,
			Path:       p.path,
			Endpoint:   p.endpoint,
			Family:     "https",
			UA:         p.ua,
			BodySample: p.body,
			Reason:     p.reason,
			Approvers:  []string{"ops"},
			CreatedAt:  time.Now().Add(-time.Duration(r.Intn(30)) * time.Minute),
			ExpiresAt:  time.Now().Add(time.Duration(20+r.Intn(60)) * time.Minute),
		})
		last = id
	}
	return last
}

func devSeedWipe(g *Gateway) error {
	for _, q := range []string{
		`DELETE FROM actions`,
		`DELETE FROM sessions`,
		`DELETE FROM devices`,
		`DELETE FROM credentials`,
		`DELETE FROM credential_secrets`,
		`DELETE FROM wg_peers`,
		`DELETE FROM peer_api_tokens`,
	} {
		if _, err := g.db.Exec(q); err != nil {
			return fmt.Errorf("%s: %w", q, err)
		}
	}
	// In-memory state was populated from the now-empty tables on boot.
	// Clear the agent map so the registry rebuilds from the fresh rows
	// below; otherwise stale Agent entries would shadow seeded data.
	if g.agents != nil {
		g.agents.mu.Lock()
		for ip := range g.agents.agents {
			delete(g.agents.agents, ip)
		}
		g.agents.mu.Unlock()
	}
	return nil
}

// devSeedRefreshRegistries re-runs the boot-time loads against the
// freshly populated tables so the in-memory registries match what's
// on disk before the dashboard starts serving.
func devSeedRefreshRegistries(g *Gateway, devices []devSeedDevice) {
	if g.onboard != nil {
		if err := g.onboard.Load(g.db); err != nil {
			log.Printf("dev-seed: onboard reload: %v", err)
		}
	}
	for _, d := range devices {
		g.agents.Seed(d.ip)
	}
	g.agents.LoadSessions(g.db)
}

func devSeedLoadDeviceList(db *sql.DB) []devSeedDevice {
	rows, err := db.Query(`SELECT id, COALESCE(name,''), COALESCE(profile,'') FROM devices`)
	if err != nil {
		log.Printf("dev-seed: list devices: %v", err)
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []devSeedDevice
	for rows.Next() {
		var d devSeedDevice
		if err := rows.Scan(&d.ip, &d.name, &d.profile); err != nil {
			log.Printf("dev-seed: scan device row: %v", err)
			continue
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		log.Printf("dev-seed: iterate devices: %v", err)
	}
	return out
}

func devSeedID(r *rand.Rand) string {
	return devSeedHex(r, 16)
}

func devSeedHex(r *rand.Rand, n int) string {
	const hexc = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hexc[r.Intn(16)]
	}
	return string(b)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
