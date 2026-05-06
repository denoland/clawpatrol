import { useEffect, useRef, useState } from "react";
import * as Plot from "@observablehq/plot";
import { getAnalytics, type Agent, type EventRecord } from "../lib/api";


const RANGES = [
  "1m", "5m", "15m", "30m", "1h", "6h", "24h",
] as const;
type Range = typeof RANGES[number];
type ColorBy = "host" | "status" | "device";
type Scale = "log" | "linear";

const RANGE_MS: Record<Range, number> = {
  "1m": 60e3, "5m": 300e3, "15m": 900e3,
  "30m": 1800e3, "1h": 3600e3, "6h": 21600e3,
  "24h": 86400e3,
};

// --- query string helpers ---

function qsGet(key: string, fallback: string): string {
  const h = window.location.hash;
  const qi = h.indexOf("?");
  if (qi < 0) return fallback;
  const p = new URLSearchParams(h.slice(qi));
  return p.get(key) ?? fallback;
}

function qsSet(key: string, value: string) {
  const h = window.location.hash;
  const qi = h.indexOf("?");
  const base = qi < 0 ? h : h.slice(0, qi);
  const p = new URLSearchParams(qi < 0 ? "" : h.slice(qi));
  p.set(key, value);
  window.location.hash = base + "?" + p.toString();
}

function useQS<T extends string>(
  key: string, fallback: T, valid: readonly T[],
): [T, (v: T) => void] {
  const init = qsGet(key, fallback) as T;
  const [val, setVal] = useState(
    valid.includes(init) ? init : fallback,
  );
  const set = (v: T) => { setVal(v); qsSet(key, v); };
  return [val, set];
}

// --- page ---

export function AnalyticsPage({ ip, agents }: {
  ip?: string;
  agents: Agent[];
}) {
  const deviceName = ip
    ? agents.find(a => a.ip === ip)?.hostname || ip
    : undefined;
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [range, setRange] =
    useQS("range", "1h" as Range, RANGES);
  const [filterDevice, setFilterDevice] = useState<
    string | null
  >(null);
  const [filterHost, setFilterHost] = useState<
    string | null
  >(null);
  const isGlobal = !ip;
  const agentNames = new Map(
    agents.map(a => [a.ip, a.hostname || a.ip]),
  );

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      getAnalytics({ range, agent: ip, limit: 5000 })
        .then((r) => { if (!cancelled) setEvents(r.events); })
        .catch(() => {});
    };
    load();
    const t = setInterval(load, 10000);
    return () => { cancelled = true; clearInterval(t); };
  }, [ip, range]);

  // Client-side filters from bar chart clicks
  const filtered = events.filter((e) => {
    if (filterDevice && e.agent_ip !== filterDevice)
      return false;
    if (filterHost && e.host !== filterHost) return false;
    return true;
  });
  const hasFilter = filterDevice || filterHost;
  const filterLabel = filterDevice
    ? agentNames.get(filterDevice) ?? filterDevice
    : filterHost ?? "";

  // --- summary stats ---
  const stats = (() => {
    const n = filtered.length;
    if (n === 0) return { n: 0, avg: 0, p99: 0, errPct: 0, devices: 0 };
    const lats = filtered
      .map(e => e.ms).filter(m => m > 0)
      .sort((a, b) => a - b);
    const avg = lats.length
      ? Math.round(lats.reduce((a, b) => a + b, 0) / lats.length) : 0;
    const p99 = lats.length
      ? lats[Math.min(Math.floor(lats.length * 0.99), lats.length - 1)] : 0;
    const errs = filtered.filter(e => (e.status ?? 0) >= 400).length;
    const errPct = n > 0 ? (errs / n) * 100 : 0;
    const devices = new Set(
      filtered.map(e => e.agent_ip).filter(Boolean),
    ).size;
    return { n, avg, p99, errPct, devices };
  })();

  return (
    <main className="flex-1 mx-auto w-full max-w-[1100px] px-4 sm:px-6 py-8 space-y-8">
      <div className="flex items-baseline justify-between flex-wrap gap-3">
        <div className="flex items-baseline gap-2">
          <a href="#/" className="text-[13px] text-[#a3a3a3] hover:text-[#171717]">
            clawpatrol
          </a>
          <span className="text-[13px] text-[#a3a3a3]">/</span>
          {deviceName ? (
            <>
              <a
                href={`#/device/${encodeURIComponent(ip!)}`}
                className="text-[13px] text-[#a3a3a3] hover:text-[#171717]"
              >
                {deviceName}
              </a>
              <span className="text-[13px] text-[#a3a3a3]">/</span>
            </>
          ) : null}
          <span className="text-[13px] text-[#525252]">analytics</span>
          {hasFilter && (
            <button
              onClick={() => { setFilterDevice(null); setFilterHost(null); }}
              className="ml-3 px-2 py-0.5 rounded text-[13px] border border-[#171717] bg-[#171717] text-white flex items-center gap-1.5 self-center"
            >
              {filterLabel}
              <span className="text-[10px]">&times;</span>
            </button>
          )}
        </div>
        <Toggle
          options={[...RANGES]}
          value={range}
          onChange={setRange}
        />
      </div>

      <div className={
        "bg-white border border-[#e5e5e5] rounded grid grid-cols-2 divide-x divide-[#e5e5e5] "
        + (isGlobal ? "sm:grid-cols-4 lg:grid-cols-5" : "sm:grid-cols-4")
      }>
        <Stat label="Requests" value={stats.n.toLocaleString()} />
        <Stat label="Avg" value={stats.avg ? fmtMs(stats.avg) : "—"} />
        <Stat label="p99" value={stats.p99 ? fmtMs(stats.p99) : "—"} />
        <Stat label="Errors"
          value={stats.errPct ? stats.errPct.toFixed(1) + "%" : "0%"}
          tone={stats.errPct >= 5 ? "warn" : undefined} />
        {isGlobal && (
          <Stat label="Devices"
            value={stats.devices.toLocaleString()} />
        )}
      </div>

      <LatencyChart
        filtered={filtered}
        isGlobal={isGlobal}
        agents={agents}
        range={range}
      />

      <div className={"grid gap-4 " + (isGlobal ? "grid-cols-1 md:grid-cols-2" : "grid-cols-1")}>
        {isGlobal && (
          <BarList
            title="By device"
            events={events}
            field="agent_ip"
            active={filterDevice}
            labelFn={(v) => agentNames.get(v) ?? v}
            onClickFn={(v) => {
              setFilterDevice(filterDevice === v ? null : v);
              setFilterHost(null);
            }}
          />
        )}
        <BarList
          title="By host"
          events={events}
          field="host"
          active={filterHost}
          onClickFn={(v) => {
            setFilterHost(filterHost === v ? null : v);
            setFilterDevice(null);
          }}
        />
      </div>

      <TopRoutes events={filtered} />
    </main>
  );
}

function fmtMs(ms: number): string {
  if (ms >= 1000) return (ms / 1000).toFixed(1) + "s";
  return ms + "ms";
}


function Stat({ label, value, tone }: {
  label: string;
  value: string;
  tone?: "warn";
}) {
  return (
    <div className="flex flex-col gap-1.5 px-5 py-4">
      <span className="text-[10px] uppercase tracking-[.12em] text-[#a3a3a3]">
        {label}
      </span>
      <span className={
        "text-[22px] font-semibold leading-none tabular-nums tracking-tight "
        + (tone === "warn" ? "text-[#b91c1c]" : "text-[#171717]")
      }>
        {value}
      </span>
    </div>
  );
}

// --- event list (time-filtered) ---


// --- stable color from string hash ---

function stableIndex(s: string, n: number): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = Math.imul(31, h) + s.charCodeAt(i) | 0;
  }
  return ((h % n) + n) % n;
}

// Cool-leaning Tailwind -700 shades. Cohesive intensity, distinct hues,
// no rainbow-toy vibe. Used for chart series (one color per host /
// device); bars use a rank-grayscale ramp instead.
const PALETTE = [
  "#1d4ed8", "#0f766e", "#7c3aed", "#0369a1",
  "#15803d", "#a16207", "#c2410c", "#be185d",
  "#4338ca", "#0e7490", "#65a30d", "#9f1239",
];
const hostColor = (s: string) => PALETTE[stableIndex(s, PALETTE.length)];
const deviceColor = (s: string) =>
  PALETTE[(stableIndex(s, PALETTE.length) + 6) % PALETTE.length];

// Status: Tailwind -700 (desaturated vs original -600). Used both in
// scatter legend and EventRow status text.
const STATUS_COLORS = {
  "2xx": "#15803d", "3xx": "#a16207", "4xx": "#c2410c",
  "5xx": "#b91c1c", "—": "#a3a3a3",
} as const;

// --- chart ---

function LatencyChart({ filtered, isGlobal, agents, range }: {
  filtered: EventRecord[];
  isGlobal: boolean;
  agents: Agent[];
  range: Range;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const colorOptions: ColorBy[] = isGlobal
    ? ["device", "host", "status"]
    : ["host", "status"];
  const [colorBy, setColorBy] =
    useQS("color", colorOptions[0], colorOptions);
  const [scale, setScale] =
    useQS("scale", "log" as Scale, ["log", "linear"]);

  const agentNames = new Map(
    agents.map(a => [a.ip, a.hostname || a.ip]),
  );

  useEffect(() => {
    if (!ref.current || filtered.length === 0) return;

    const dots = filtered
      .filter((e) => e.ms > 0)
      .map((e) => ({
        t: new Date(e.ts),
        ms: e.ms,
        host: e.host,
        id: e.id,
        device: agentNames.get(e.agent_ip ?? "") ?? e.agent_ip ?? "?",
        statusCode: e.status ?? 0,
        status: e.status
          ? e.status >= 500 ? "5xx"
          : e.status >= 400 ? "4xx"
          : e.status >= 300 ? "3xx"
          : "2xx"
          : "\u2014",
      }));

    const colorField =
      colorBy === "status" ? "status"
      : colorBy === "device" ? "device"
      : "host";

    const vals = [...new Set(dots.map(
      d => d[colorField] as string,
    ))];

    const colorCfg = colorBy === "status"
      ? {
          domain: ["2xx", "3xx", "4xx", "5xx", "\u2014"],
          range: [
            STATUS_COLORS["2xx"], STATUS_COLORS["3xx"],
            STATUS_COLORS["4xx"], STATUS_COLORS["5xx"],
            STATUS_COLORS["\u2014"],
          ],
          legend: true,
        }
      : {
          domain: vals,
          range: vals.map((v) =>
            colorBy === "device" ? deviceColor(v) : hostColor(v),
          ),
          legend: true,
        };

    const chart = Plot.plot({
      width: ref.current.clientWidth,
      height: 300,
      marginLeft: 52,
      marginBottom: 28,
      marginTop: 12,
      marginRight: 8,
      style: {
        background: "transparent",
        fontSize: "11px",
        fontFamily: "ui-sans-serif, system-ui, sans-serif",
        color: "#525252",
      },
      y: {
        type: scale,
        label: null,
        grid: true,
        nice: true,
        ...(scale === "log"
          ? {
              ticks: [1, 10, 100, 1000, 10000],
              tickFormat: (v: number) =>
                v >= 1000 ? `${v / 1000}k` : `${v}`,
            }
          : {
              domain: [
                0,
                Math.max(100, ...dots.map(d => d.ms)) * 1.1,
              ],
            }),
      },
      x: {
        type: "time",
        label: null,
        domain: [
          new Date(Date.now() - RANGE_MS[range]),
          new Date(),
        ],
      },
      color: colorCfg,
      marks: [
        // Soft grid: redraw with very light stroke (Plot's default
        // grid is too dark against the muted palette).
        Plot.gridY({ stroke: "#f0f0f0", strokeWidth: 1 }),
        Plot.gridX({ stroke: "#f5f5f5", strokeWidth: 1 }),
        // Dots: smaller radius, white stroke ring for separation in
        // dense clusters, lower opacity so density reads as shading.
        Plot.dot(dots, {
          x: "t",
          y: "ms",
          fill: colorField,
          r: 2.5,
          fillOpacity: 0.75,
          stroke: "white",
          strokeWidth: 0.5,
          href: (d: typeof dots[0]) =>
            d.id ? `#/request/${d.id}` : undefined,
          title: (d: typeof dots[0]) =>
            `${d.host}\n${d.device}\n${d.statusCode || "\u2014"} \u2022 ${d.ms}ms`,
        }),
        Plot.tip(dots, Plot.pointer({
          x: "t",
          y: "ms",
          title: (d: typeof dots[0]) =>
            `${d.host}\n${d.device}\n${d.statusCode || "\u2014"} \u2022 ${d.ms}ms`,
        })),
      ],
    });

    // SVG <a> elements use xlink:href and do full
    // navigation — intercept clicks so the hash router
    // handles them instead.
    chart.addEventListener("click", (evt) => {
      const a = (evt.target as Element).closest("a");
      const href = a?.getAttribute("href")
        ?? a?.getAttributeNS(
          "http://www.w3.org/1999/xlink", "href",
        );
      if (href?.startsWith("#/request/")) {
        evt.preventDefault();
        window.location.hash = href;
      }
    });
    chart.querySelectorAll("a").forEach((a) => {
      (a as unknown as HTMLElement).style.cursor = "pointer";
    });

    // Make legend swatches clickable when colored by device
    if (colorBy === "device") {
      const nameToIP = new Map(
        agents.map(a => [a.hostname || a.ip, a.ip]),
      );
      chart.querySelectorAll(
        "[aria-label='color'] [aria-label]",
      ).forEach((el) => {
        const label = el.getAttribute("aria-label") ?? "";
        const devIP = nameToIP.get(label);
        if (!devIP) return;
        const span = el as HTMLElement;
        span.style.cursor = "pointer";
        span.addEventListener("click", (e) => {
          e.stopPropagation();
          window.location.hash =
            `#/analytics/${encodeURIComponent(devIP)}`;
        });
      });
    }

    ref.current.replaceChildren(chart);
    return () => chart.remove();
  }, [filtered, colorBy, scale, range]);

  return (
    <section className="bg-white border border-[#e5e5e5] rounded overflow-hidden">
      <header className="flex items-center justify-between px-4 py-2.5 border-b border-[#e5e5e5]">
        <span className="text-[10px] uppercase tracking-[.12em] text-[#a3a3a3]">
          Latency
        </span>
        <div className="flex items-center gap-3">
          <Toggle
            options={colorOptions}
            value={colorBy}
            onChange={setColorBy}
          />
          <Toggle
            options={["log", "linear"] as Scale[]}
            value={scale}
            onChange={setScale}
          />
        </div>
      </header>
      <div ref={ref} className="p-4 min-h-[320px]" />
    </section>
  );
}

// --- toggle ---

function Toggle<T extends string>({
  options, value, onChange,
}: {
  options: T[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div className="flex text-[10px] border border-[#e5e5e5] rounded overflow-hidden">
      {options.map((o) => (
        <button
          key={o}
          onClick={() => onChange(o)}
          className={
            "px-2 py-0.5 " +
            (o === value
              ? "bg-[#171717] text-white"
              : "text-[#525252] hover:bg-[#fafafa]")
          }
        >
          {o}
        </button>
      ))}
    </div>
  );
}

// --- top routes ---

type RouteRow = {
  key: string;
  method: string;
  host: string;
  path: string;
  count: number;
  avgMs: number;
  p99Ms: number;
};

function TopRoutes({ events }: { events: EventRecord[] }) {
  const [sortBy, setSortBy] = useState<
    "count" | "avgMs" | "p99Ms"
  >("count");

  const byRoute = new Map<string, number[]>();
  for (const e of events) {
    if (!e.ms) continue;
    const k = `${e.method ?? ""}|${e.host}|${e.path ?? ""}`;
    const arr = byRoute.get(k);
    if (arr) arr.push(e.ms);
    else byRoute.set(k, [e.ms]);
  }

  const rows: RouteRow[] = [];
  for (const [k, latencies] of byRoute) {
    const [method, host, path] = k.split("|");
    const sorted = latencies.slice().sort((a, b) => a - b);
    const avg = sorted.reduce((a, b) => a + b, 0) /
      sorted.length;
    const p99i = Math.floor(sorted.length * 0.99);
    rows.push({
      key: k,
      method,
      host,
      path,
      count: sorted.length,
      avgMs: Math.round(avg),
      p99Ms: sorted[Math.min(p99i, sorted.length - 1)],
    });
  }

  rows.sort((a, b) => b[sortBy] - a[sortBy]);
  const maxCount = rows.length ? rows[0].count : 0;

  const hdr = (
    label: string,
    field: "count" | "avgMs" | "p99Ms",
  ) => (
    <th
      className="px-3 sm:px-[14px] py-[9px] text-right text-[10px] font-medium uppercase tracking-[.12em] text-[#a3a3a3] cursor-pointer hover:text-[#525252] select-none"
      onClick={() => setSortBy(field)}
    >
      {label}{sortBy === field ? " \u25BE" : ""}
    </th>
  );

  return (
    <section className="bg-white border border-[#e5e5e5] rounded overflow-hidden">
      <table className="w-full table-fixed text-[11px]">
        <thead>
          <tr className="border-b border-[#e5e5e5]">
            <th className="px-3 sm:px-[14px] py-[9px] text-left text-[10px] uppercase tracking-[.12em] text-[#a3a3a3] font-medium">
              Top routes
            </th>
            {hdr("Reqs", "count")}
            {hdr("Avg", "avgMs")}
            {hdr("p99", "p99Ms")}
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 20).map((d) => {
            const pct = maxCount > 0
              ? (d.count / maxCount) * 100 : 0;
            return (
              <tr
                key={d.key}
                className="border-b border-[#f5f5f5] hover:bg-[#f9f9f9] transition-colors"
              >
                <td className="px-3 sm:px-[14px] py-[9px] font-mono truncate max-w-0 align-middle" title={`${d.method} ${d.host}${d.path}`}>
                  <span className="text-[#a3a3a3]">{d.method}</span>{" "}{d.host}<span className="text-[#525252]">{d.path}</span>
                </td>
                <td className="px-3 sm:px-[14px] py-[9px] text-right whitespace-nowrap align-middle">
                  <div className="flex items-center justify-end gap-1.5">
                    <div className="w-12 h-1.5 bg-[#f5f5f5] rounded-full">
                      <div className="h-full bg-[#a3a3a3] rounded-full" style={{ width: `${pct}%` }} />
                    </div>
                    <span className="w-6 text-right tabular-nums">{d.count}</span>
                  </div>
                </td>
                <td className="px-3 sm:px-[14px] py-[9px] text-right text-[#525252] tabular-nums align-middle">{fmtMs(d.avgMs)}</td>
                <td className="px-3 sm:px-[14px] py-[9px] text-right text-[#525252] tabular-nums align-middle">{fmtMs(d.p99Ms)}</td>
              </tr>
            );
          })}
          {rows.length === 0 && (
            <tr>
              <td colSpan={4} className="px-1 py-6 text-center text-[11px] text-[#a3a3a3]">
                No data in this time range
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </section>
  );
}

// --- horizontal bar list ---

function BarList({ title, events, field, active, labelFn, onClickFn }: {
  title: string;
  events: EventRecord[];
  field: "host" | "agent_ip";
  active?: string | null;
  labelFn?: (v: string) => string;
  onClickFn?: (v: string) => void;
}) {
  const counts = new Map<string, number>();
  for (const e of events) {
    const v = (field === "host" ? e.host : e.agent_ip) ?? "";
    if (!v) continue;
    counts.set(v, (counts.get(v) ?? 0) + 1);
  }
  const items = [...counts.entries()]
    .map(([k, v]) => ({ key: k, label: labelFn ? labelFn(k) : k, value: v }))
    .sort((a, b) => b.value - a.value);

  const max = items.length ? items[0].value : 0;

  return (
    <section className="bg-white border border-[#e5e5e5] rounded overflow-hidden">
      <header className="px-4 py-2.5 border-b border-[#e5e5e5]">
        <span className="text-[10px] uppercase tracking-[.12em] text-[#a3a3a3]">
          {title}
        </span>
      </header>
      <div className="p-3 space-y-0.5">
        {items.slice(0, 10).map((item) => {
          const pct = max > 0 ? (item.value / max) * 100 : 0;
          const isActive = active === item.key;
          const barColor = isActive ? "#171717" : "#525252";
          return (
            <div
              key={item.key}
              className={
                "flex items-center gap-2 px-1 py-0.5 rounded cursor-pointer "
                + (isActive ? "bg-[#f5f5f5]" : "hover:bg-[#fafafa]")
              }
              onClick={onClickFn ? () => onClickFn(item.key) : undefined}
            >
              <span className={"w-32 truncate text-[11px] " + (isActive ? "text-[#171717] font-semibold" : "text-[#525252]")} title={item.label}>
                {item.label}
              </span>
              <div className="flex-1 h-2 bg-[#f5f5f5] rounded-full">
                <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: barColor }} />
              </div>
              <span className="w-8 text-right text-[11px] text-[#a3a3a3] tabular-nums">
                {item.value}
              </span>
            </div>
          );
        })}
        {items.length === 0 && (
          <div className="py-4 text-center text-[11px] text-[#a3a3a3]">
            No data in this time range
          </div>
        )}
      </div>
    </section>
  );
}
