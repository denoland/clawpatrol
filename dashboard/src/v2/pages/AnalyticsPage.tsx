import * as Plot from "@observablehq/plot";
import { useEffect, useMemo, useRef, useState } from "react";
import { type Agent, type EventRecord, getAnalytics, type LatencyDot } from "../../lib/api";
import { Card } from "../cards/Card";
import { PageHeader } from "../cards/PageHeader";

type Range = "1h" | "24h" | "7d" | "30d";

// Analytics — counts + top hosts / top devices + latency dot plot
// and histogram (mirrors unclaw's LatencySection). The /api/analytics
// `dots` array is shaped to match unclaw's so the chart code is
// effectively the same. LLM cost / decisions panels intentionally not
// ported — they're out of scope here.
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
    dots: LatencyDot[];
  } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancel = false;
    setLoading(true);
    getAnalytics({ range, agent: agentFilter || undefined, limit: 5000 })
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

      <LatencySection dots={data?.dots ?? []} agentLabel={agentLabel} />

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

// --- Latency section (dot plot + histogram), ported from unclaw ---

type ColorBy = "host" | "agent" | "status";

const MS_TICKS = [0.1, 1, 10, 100, 1000, 10000];

function fmtMs(v: number): string {
  if (v >= 1000) return `${v / 1000}k`;
  if (v < 1) return `${v}`;
  return `${Math.round(v)}`;
}

function statusCls(s: number): string {
  if (s < 300) return "2xx";
  if (s < 400) return "3xx";
  if (s < 500) return "4xx";
  return "5xx";
}

function LatencySection({
  dots: raw,
  agentLabel,
}: {
  dots: LatencyDot[];
  agentLabel: Map<string, string>;
}) {
  const [colorBy, setColorBy] = useState<ColorBy>("host");
  const [logScale, setLogScale] = useState(true);

  const dots = useMemo(
    () =>
      raw.map((d) => ({
        t: new Date(d.t),
        ms: Math.max(d.us / 1000, 0.1),
        status: statusCls(d.status),
        host: d.host,
        agent: agentLabel.get(d.agent) ?? d.agent ?? "?",
        id: d.id,
      })),
    [raw, agentLabel],
  );
  const logDots = useMemo(() => dots.map((d) => ({ ...d, logMs: Math.log10(d.ms) })), [dots]);

  return (
    <Card title="Response latency">
      <div className="flex items-center gap-3 mb-3">
        <Toggle
          options={["log", "linear"] as const}
          value={logScale ? "log" : "linear"}
          onChange={(v) => setLogScale(v === "log")}
        />
        <div className="ml-auto">
          <Toggle
            options={["host", "agent", "status"] as const}
            value={colorBy}
            onChange={setColorBy}
          />
        </div>
      </div>
      {dots.length === 0 ? (
        <div className="py-8 text-center text-sm text-text-muted">No data.</div>
      ) : (
        <>
          <ObsPlot
            render={(w) =>
              Plot.dot(dots, {
                x: "t",
                y: "ms",
                fill: colorBy,
                r: 2,
                fillOpacity: 0.5,
                tip: true,
              }).plot({
                width: w,
                height: 280,
                x: { label: null },
                y: {
                  type: logScale ? "log" : "linear",
                  label: "Duration (ms)",
                  grid: true,
                  nice: true,
                  ...(logScale ? { ticks: MS_TICKS, tickFormat: fmtMs } : {}),
                },
                color: { legend: true },
              })
            }
            deps={[dots, colorBy, logScale]}
          />
          <h4 className="text-[10px] font-medium uppercase text-text-muted mt-3 mb-1">
            Latency histogram
          </h4>
          <ObsPlot
            render={(w) =>
              logScale
                ? Plot.rectY(
                    logDots,
                    Plot.binX<Plot.RectYOptions>(
                      { y: "count" },
                      { x: "logMs", fill: colorBy, thresholds: 60, inset: 0, tip: true },
                    ),
                  ).plot({
                    width: w,
                    height: 160,
                    x: {
                      label: "Duration (ms)",
                      ticks: MS_TICKS.map(Math.log10),
                      tickFormat: (d: number) => fmtMs(Math.round(Math.pow(10, d))),
                    },
                    y: { label: null, grid: true },
                    color: { legend: false },
                  })
                : Plot.rectY(
                    dots,
                    Plot.binX<Plot.RectYOptions>(
                      { y: "count" },
                      { x: "ms", fill: colorBy, thresholds: 40, inset: 0, tip: true },
                    ),
                  ).plot({
                    width: w,
                    height: 160,
                    x: { label: "Duration (ms)" },
                    y: { label: null, grid: true },
                    color: { legend: false },
                  })
            }
            deps={[logScale ? logDots : dots, colorBy, logScale]}
          />
        </>
      )}
    </Card>
  );
}

function ObsPlot({
  render,
  deps,
}: {
  render: (w: number) => HTMLElement | SVGSVGElement;
  deps: unknown[];
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!ref.current) return;
    const w = ref.current.clientWidth || 800;
    const el = render(w);
    ref.current.replaceChildren(el);
    return () => el.remove();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return <div ref={ref} />;
}

function Toggle<T extends string>({
  options,
  value,
  onChange,
}: {
  options: readonly T[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div className="flex gap-0.5">
      {options.map((o) => (
        <button
          key={o}
          type="button"
          onClick={() => onChange(o)}
          className={
            "px-2 py-0.5 text-[10px] font-medium " +
            (o === value
              ? "bg-text text-canvas-light"
              : "bg-canvas-muted text-text-muted hover:bg-canvas-dark")
          }
        >
          {o}
        </button>
      ))}
    </div>
  );
}
