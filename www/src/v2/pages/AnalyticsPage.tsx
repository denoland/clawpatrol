import { useEffect, useMemo, useState } from "react";
import { type Agent, type EventRecord, getAnalytics } from "../../lib/api";
import { Card } from "../cards/Card";
import { PageHeader } from "../cards/PageHeader";

type Range = "1h" | "24h" | "7d" | "30d";

// Analytics — counts + top hosts / top devices. unclaw renders a
// 9-panel canvas dashboard (Plot dot-charts, status-over-time,
// latency grid, sizes grid, LLM cost-over-time) backed by
// /api/analytics shapes clawpatrol doesn't expose. We project the
// `events + by_device + by_host` clawpatrol returns into a much
// simpler summary, and call out the missing series as gaps.
export function V2AnalyticsPage({ agents }: { agents: Agent[] }) {
  const [range, setRange] = useState<Range>("24h");
  const [agentFilter, setAgentFilter] = useState("");
  const [data, setData] = useState<{
    events: EventRecord[];
    total: number;
    total_count: number;
    error_count: number;
    by_device: { key: string; count: number }[];
    by_host: { key: string; count: number }[];
  } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancel = false;
    setLoading(true);
    getAnalytics({ range, agent: agentFilter || undefined, limit: 500 })
      .then((d) => {
        if (!cancel) setData(d);
      })
      .catch(() => {
        if (!cancel) setData(null);
      })
      .finally(() => {
        if (!cancel) setLoading(false);
      });
    return () => {
      cancel = true;
    };
  }, [range, agentFilter]);

  const agentLabel = useMemo(() => {
    const m = new Map<string, string>();
    for (const a of agents) m.set(a.ip, a.hostname || a.ip);
    return m;
  }, [agents]);

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader title="Analytics" subhead={`Traffic over the last ${range}.`}>
        <select
          value={range}
          onChange={(e) => setRange(e.target.value as Range)}
          className="border border-canvas-dark bg-canvas-light text-sm px-2 py-1"
        >
          <option value="1h">1h</option>
          <option value="24h">24h</option>
          <option value="7d">7d</option>
          <option value="30d">30d</option>
        </select>
        <select
          value={agentFilter}
          onChange={(e) => setAgentFilter(e.target.value)}
          className="border border-canvas-dark bg-canvas-light text-sm px-2 py-1"
        >
          <option value="">All agents</option>
          {agents.map((a) => (
            <option key={a.ip} value={a.ip}>
              {a.hostname || a.ip}
            </option>
          ))}
        </select>
      </PageHeader>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <Stat label="Requests" value={loading ? "…" : fmtCount(data?.total_count ?? 0)} />
        <Stat label="Errors" value={loading ? "…" : fmtCount(data?.error_count ?? 0)} />
        <Stat label="Unique devices" value={loading ? "…" : String(data?.by_device.length ?? 0)} />
        <Stat label="Unique hosts" value={loading ? "…" : String(data?.by_host.length ?? 0)} />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Top devices" count={data?.by_device.length ?? 0} tight>
          {!data?.by_device.length ? (
            <div className="px-4 py-8 text-center text-sm text-text-muted">No data.</div>
          ) : (
            <ul className="divide-y divide-canvas-dark">
              {data.by_device.slice(0, 12).map((d) => (
                <li key={d.key} className="px-4 py-2 flex items-center justify-between">
                  <span className="truncate">{agentLabel.get(d.key) ?? d.key}</span>
                  <span className="text-text-muted text-xs">{fmtCount(d.count)}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Top hosts" count={data?.by_host.length ?? 0} tight>
          {!data?.by_host.length ? (
            <div className="px-4 py-8 text-center text-sm text-text-muted">No data.</div>
          ) : (
            <ul className="divide-y divide-canvas-dark">
              {data.by_host.slice(0, 12).map((h) => (
                <li key={h.key} className="px-4 py-2 flex items-center justify-between">
                  <span className="truncate font-mono text-xs">{h.key}</span>
                  <span className="text-text-muted text-xs">{fmtCount(h.count)}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title="What's missing vs unclaw">
        <div className="text-sm text-text-muted space-y-1">
          <p>
            clawpatrol's <code className="font-mono text-xs">/api/analytics</code> returns events
            and aggregates by host/device, but doesn't expose unclaw's per-millisecond dot streams,
            latency / size histograms, status-class-over-time, or LLM cost / token telemetry.
          </p>
          <p>
            The canvas-based dot charts, gridded heatmaps, and LLM cost-over-time panels that
            unclaw's <code className="font-mono text-xs">AnalyticsPage</code> renders would need new
            backend endpoints to power. Out of scope for cl-r3e (no new endpoints).
          </p>
        </div>
      </Card>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="border border-canvas-dark bg-canvas-light px-4 py-3">
      <div className="text-xs uppercase tracking-wider text-text-muted">{label}</div>
      <div className="text-2xl font-semibold text-text mt-1">{value}</div>
    </div>
  );
}

function fmtCount(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return (n / 1000).toFixed(n < 10_000 ? 1 : 0) + "k";
  return (n / 1_000_000).toFixed(1) + "M";
}
