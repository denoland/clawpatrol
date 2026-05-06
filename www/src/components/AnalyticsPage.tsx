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

  return (
    <main className="flex-1 mx-auto w-full max-w-[1100px] px-4 sm:px-6 py-8 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-baseline gap-2">
          <a href="#/" className="text-[11px] text-[#a3a3a3] hover:text-[#171717]">
            clawpatrol
          </a>
          <span className="text-[11px] text-[#a3a3a3]">/</span>
          {deviceName ? (
            <>
              <a
                href={`#/device/${encodeURIComponent(ip!)}`}
                className="text-[16px] font-semibold text-[#171717] hover:underline"
              >
                {deviceName}
              </a>
              <span className="text-[11px] text-[#a3a3a3]">/</span>
            </>
          ) : null}
          <span className="text-[11px] text-[#525252]">analytics</span>
          {ip && (
            <a
              href="#/analytics"
              className="ml-2 px-2.5 py-0.5 rounded text-[11px] border border-[#171717] bg-[#171717] text-white flex items-center gap-1.5 no-underline"
            >
              {deviceName}
              <span className="text-[10px]">&times;</span>
            </a>
          )}
          {hasFilter && (
            <button
              onClick={() => { setFilterDevice(null); setFilterHost(null); }}
              className="ml-2 px-2.5 py-0.5 rounded text-[11px] border border-[#525252] bg-[#525252] text-white flex items-center gap-1.5"
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

      <div className={"grid gap-4 " + (isGlobal ? "grid-cols-1 md:grid-cols-2" : "grid-cols-1")}>
        {isGlobal && (
          <BarCard
            title="Count by device"
            events={events}
            field="agent_ip"
            active={filterDevice}
            labelFn={(v) => agentNames.get(v) ?? v}
            colorFn={deviceColor}
            onClickFn={(v) => {
              setFilterDevice(
                filterDevice === v ? null : v,
              );
              setFilterHost(null);
            }}
          />
        )}
        <BarCard
          title="Count by host"
          events={events}
          field="host"
          active={filterHost}
          onClickFn={(v) => {
            setFilterHost(filterHost === v ? null : v);
            setFilterDevice(null);
          }}
        />
      </div>
      <LatencyChart
        filtered={filtered}
        isGlobal={isGlobal}
        agents={agents}
        range={range}
      />
      <TopRoutes events={filtered} />
      <EventList events={filtered} />
    </main>
  );
}

// --- event list (time-filtered) ---

function EventList({ events }: { events: EventRecord[] }) {
  return (
    <div className="bg-white border border-[#e5e5e5] rounded overflow-hidden"
      style={{ height: "500px" }}
    >
      <div className="flex items-center px-4 py-2.5 text-[10px] uppercase tracking-[.12em] text-[#a3a3a3] border-b border-[#e5e5e5]">
        <span>REQUESTS</span>
        <span className="ml-2 tabular-nums">{events.length}</span>
      </div>
      <div className="flex-1 overflow-y-auto" style={{ height: "calc(100% - 36px)" }}>
        {events.length === 0 ? (
          <div className="px-5 py-8 text-center text-[11px] text-[#a3a3a3]">
            No requests in this time range
          </div>
        ) : events.map((e, i) => (
          <EventRow key={e.id || i} ev={e} />
        ))}
      </div>
    </div>
  );
}

function EventRow({ ev }: { ev: EventRecord }) {
  const onClick = ev.id
    ? () => { window.location.hash = `#/request/${ev.id}`; }
    : undefined;
  const t = new Date(ev.ts);
  const time = t.toLocaleTimeString([], { hour12: false })
    + "." + String(t.getMilliseconds()).padStart(3, "0");
  const status = ev.status || 0;
  const statusColor =
    status >= 500 ? "text-[#dc2626]"
    : status >= 400 ? "text-[#ea580c]"
    : status >= 300 ? "text-[#ca8a04]"
    : status >= 200 ? "text-[#16a34a]"
    : "text-[#737373]";
  const path = ev.path ?? "";
  const sep = path.startsWith("/") ? "" : " ";
  return (
    <div
      onClick={onClick}
      className={
        "px-4 py-2 border-b border-[#f5f5f5] flex items-center gap-3 min-w-0 transition-colors hover:bg-[#f9f9f9]"
        + (onClick ? " cursor-pointer" : "")
      }
    >
      <span className="text-[10px] tabular-nums text-[#a3a3a3] flex-shrink-0">{time}</span>
      {ev.method && (
        <span className="text-[10px] uppercase font-semibold text-[#525252] flex-shrink-0 w-[44px]">{ev.method}</span>
      )}
      <span className={"text-[11px] tabular-nums flex-shrink-0 w-[36px] " + statusColor}>
        {status || "\u2014"}
      </span>
      <span className="text-[12px] text-[#171717] truncate flex-1 min-w-0">
        <span className="text-[#737373]">{ev.host}</span>
        {sep && <span> </span>}
        <span>{path}</span>
      </span>
      <span className="text-[10px] tabular-nums text-[#a3a3a3] flex-shrink-0">
        {ev.ms}ms
      </span>
    </div>
  );
}

// --- stable color from string hash ---

function stableHue(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = Math.imul(31, h) + s.charCodeAt(i) | 0;
  }
  return ((h % 360) + 360) % 360;
}
// Hosts: warm palette (saturated, mid-lightness)
const hostColor = (s: string) =>
  `hsl(${stableHue(s)}, 70%, 45%)`;
// Devices: cool-shifted, lower saturation, darker
const deviceColor = (s: string) =>
  `hsl(${(stableHue(s) + 180) % 360}, 50%, 35%)`;

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
            "#16a34a", "#ca8a04", "#ea580c",
            "#dc2626", "#a3a3a3",
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
      height: 280,
      marginLeft: 60,
      marginBottom: 40,
      y: {
        type: scale,
        label: "Latency (ms)",
        grid: true,
        nice: true,
        ...(scale === "log"
          ? {
              ticks: [0.1, 1, 10, 100, 1000, 10000, 100000],
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
        Plot.dot(dots, {
          x: "t",
          y: "ms",
          fill: colorField,
          r: 3,
          fillOpacity: 0.7,
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
        Plot.ruleY([0]),
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
    <div className="bg-white border border-[#e5e5e5] rounded overflow-hidden">
      <div className="px-4 py-2.5 border-b border-[#e5e5e5] flex items-center justify-between">
        <span className="text-[10px] uppercase tracking-[.12em] text-[#a3a3a3]">
          Latency
        </span>
        <div className="flex items-center gap-4">
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
      </div>
      <div ref={ref} className="p-4 min-h-[320px]" />
    </div>
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
              : "text-[#737373] hover:bg-[#f5f5f5]")
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
      className="px-2 py-1.5 text-right text-[10px] font-medium uppercase text-[#a3a3a3] cursor-pointer hover:text-[#525252] select-none"
      onClick={() => setSortBy(field)}
    >
      {label}{sortBy === field ? " \u25BE" : ""}
    </th>
  );

  const fmtMs = (ms: number) => {
    if (ms >= 1000) return `${(ms / 1000).toFixed(1)}s`;
    return `${ms}ms`;
  };

  return (
    <div className="bg-white border border-[#e5e5e5] rounded overflow-hidden">
      <div className="px-4 py-2.5 text-[10px] uppercase tracking-[.12em] text-[#a3a3a3] border-b border-[#e5e5e5]">
        Top Routes
      </div>
      <table className="w-full table-fixed text-[11px]">
        <thead>
          <tr className="border-b border-[#f5f5f5]">
            <th className="px-3 py-1.5 text-left text-[10px] font-medium uppercase text-[#a3a3a3]">
              Route
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
                className="border-b border-[#f5f5f5] hover:bg-[#f9f9f9]"
              >
                <td className="px-3 py-1.5 font-mono truncate max-w-0" title={`${d.method} ${d.host}${d.path}`}>
                  <span className="text-[#a3a3a3]">{d.method}</span>{" "}{d.host}<span className="text-[#525252]">{d.path}</span>
                </td>
                <td className="px-2 py-1.5 text-right whitespace-nowrap">
                  <div className="flex items-center justify-end gap-1.5">
                    <div className="w-12 h-1.5 bg-[#f5f5f5] rounded-full">
                      <div className="h-full bg-[#a3a3a3] rounded-full" style={{ width: `${pct}%` }} />
                    </div>
                    <span className="w-6 text-right tabular-nums">{d.count}</span>
                  </div>
                </td>
                <td className="px-2 py-1.5 text-right text-[#737373] tabular-nums">{fmtMs(d.avgMs)}</td>
                <td className="px-2 py-1.5 text-right text-[#737373] tabular-nums">{fmtMs(d.p99Ms)}</td>
              </tr>
            );
          })}
          {rows.length === 0 && (
            <tr>
              <td colSpan={4} className="px-3 py-6 text-center text-[11px] text-[#a3a3a3]">
                No data in this time range
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

// --- horizontal bar card ---

function BarCard({ title, events, field, active, labelFn, colorFn, onClickFn }: {
  title: string;
  events: EventRecord[];
  field: "host" | "agent_ip";
  active?: string | null;
  labelFn?: (v: string) => string;
  colorFn?: (label: string) => string;
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
    <div className="bg-white border border-[#e5e5e5] rounded overflow-hidden">
      <div className="px-4 py-2.5 text-[10px] uppercase tracking-[.12em] text-[#a3a3a3] border-b border-[#e5e5e5]">
        {title}
      </div>
      <div className="p-3 space-y-0.5">
        {items.map((item) => {
          const pct = max > 0 ? (item.value / max) * 100 : 0;
          const isActive = active === item.key;
          return (
            <div
              key={item.key}
              className={
                "flex items-center gap-2 px-1 py-0.5 rounded cursor-pointer "
                + (isActive ? "bg-[#f0f0f0]" : "hover:bg-[#f5f5f5]")
              }
              onClick={onClickFn ? () => onClickFn(item.key) : undefined}
            >
              <span className={"w-32 truncate text-[11px] " + (isActive ? "text-[#171717] font-semibold" : "text-[#525252]")} title={item.label}>
                {item.label}
              </span>
              <div className="flex-1 h-3 bg-[#f5f5f5] rounded-full">
                <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: isActive ? "#171717" : (colorFn ? colorFn(item.label) : hostColor(item.label)) }} />
              </div>
              <span className="w-8 text-right text-[11px] text-[#737373] tabular-nums">
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
    </div>
  );
}
