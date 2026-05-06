import type { Plugin } from "vite";

// Vite middleware: when DEMO=1 in env, serve canned dashboard data
// instead of proxying to the gateway. Lets us iterate on the analytics
// UI without a live gateway.

const HOSTS = [
  "api.openai.com", "api.anthropic.com", "github.com",
  "registry.npmjs.org", "deno.clawpatrol.dev", "api.linear.app",
  "1.1.1.1", "raw.githubusercontent.com",
];
const DEVICES = [
  { ip: "10.0.0.2", hostname: "macbook-divy" },
  { ip: "10.0.0.3", hostname: "linux-build-1" },
  { ip: "10.0.0.4", hostname: "macbook-ry" },
];
const METHODS = ["GET", "POST", "PUT", "DELETE"];
const PATHS = [
  "/v1/messages", "/v1/chat/completions", "/repos/foo/bar",
  "/api/v1/issues", "/.well-known/openid-configuration",
  "/", "/health", "/v1/embeddings", "/api/v1/projects",
];

function rand<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

// Real agent traffic is bursty: idle, then a flurry of API calls
// within a few seconds (prompt → completions + tools + retries),
// then idle again. Generate by sessions, not by independent draws.
function gen(rangeMs: number, target: number) {
  const now = Date.now();
  const events: any[] = [];
  // Average burst size ~12. Sessions per device determined by target.
  const sessionsTotal = Math.max(
    DEVICES.length,
    Math.ceil(target / 12),
  );
  for (let s = 0; s < sessionsTotal && events.length < target; s++) {
    const dev = rand(DEVICES);
    const sessionHost = rand(HOSTS); // dominant host for this burst
    // Session start uniform across range. Burst length 1-30s.
    const startOffset = Math.random() * rangeMs;
    const burstMs = 1000 + Math.random() * 29000;
    // Cluster size: log-normal, average ~12, occasional 40+
    const size = Math.max(1, Math.floor(
      Math.exp(1 + Math.random() * 2.2) + Math.random() * 4,
    ));
    for (let k = 0; k < size && events.length < target; k++) {
      // Even spacing inside the burst with jitter so dots don't grid up
      const t = startOffset + (k / size) * burstMs
        + (Math.random() - 0.5) * (burstMs / size);
      const ts = now - t;
      const ms = Math.floor(
        Math.exp(Math.random() * 4 + 3) + Math.random() * 50,
      );
      const r = Math.random();
      const status = r < 0.88 ? 200 : r < 0.94 ? 304
        : r < 0.97 ? 404 : r < 0.99 ? 500 : 503;
      // 70% of events hit the session's dominant host
      const host = Math.random() < 0.7 ? sessionHost : rand(HOSTS);
      events.push({
        id: "ev_" + Math.random().toString(36).slice(2, 10),
        ts: new Date(ts).toISOString(),
        mode: "https",
        agent_ip: dev.ip,
        host,
        method: rand(METHODS),
        path: rand(PATHS),
        status,
        ms,
        in: Math.floor(Math.random() * 4096),
        out: Math.floor(Math.random() * 32768),
      });
    }
  }
  events.sort((a, b) =>
    new Date(b.ts).getTime() - new Date(a.ts).getTime(),
  );
  return events;
}

const RANGE_MS: Record<string, number> = {
  "1m": 60e3, "5m": 300e3, "15m": 900e3, "30m": 1800e3,
  "1h": 3600e3, "6h": 21600e3, "24h": 86400e3,
};

export function mockApi(): Plugin {
  return {
    name: "mock-api",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url || "";
        if (!url.startsWith("/api/")) return next();
        res.setHeader("Content-Type", "application/json");
        if (url.startsWith("/api/state")) {
          res.end(JSON.stringify({
            whoami: { user: "divy", device: "10.0.0.2",
              host: "localhost:5174" },
            integrations: [],
            agents: DEVICES.map((d) => ({
              ...d, user: "divy", os: "darwin",
              first_at: new Date(Date.now() - 86400e3).toISOString(),
              last_at: new Date().toISOString(),
              reqs: Math.floor(Math.random() * 5000),
              bytes_in: 0, bytes_out: 0,
              last_host: rand(HOSTS),
            })),
          }));
          return;
        }
        if (url.startsWith("/api/analytics")) {
          const u = new URL(url, "http://x");
          const range = u.searchParams.get("range") || "1h";
          const limit = parseInt(
            u.searchParams.get("limit") || "5000", 10,
          );
          const ms = RANGE_MS[range] || 3600e3;
          // Density scales with range so all ranges look populated.
          const n = Math.min(limit, Math.floor(ms / 1000));
          res.end(JSON.stringify({ events: gen(ms, n) }));
          return;
        }
        if (url.startsWith("/api/profiles")) {
          res.end(JSON.stringify(["default"]));
          return;
        }
        res.statusCode = 404;
        res.end("{}");
      });
    },
  };
}
