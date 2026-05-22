import * as Plot from "@observablehq/plot";
import { useEffect, useMemo, useRef, useState } from "react";
import { getAnalytics, type Agent, type EventRecord } from "../lib/api";
import { Main } from "./Main";
import { PageTitle, type Crumb } from "./PageTitle";
import { Tag } from "./Tag";

const RANGES = ["1m", "5m", "15m", "30m", "1h", "6h", "24h"] as const;
type Range = (typeof RANGES)[number];
type ColorBy = "host" | "status" | "device";
type Scale = "log" | "linear";

const RANGE_MS: Record<Range, number> = {
  "1m": 60e3,
  "5m": 300e3,
  "15m": 900e3,
  "30m": 1800e3,
  "1h": 3600e3,
  "6h": 21600e3,
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
  key: string,
  fallback: T,
  valid: readonly T[],
): [T, (v: T) => void] {
  const init = qsGet(key, fallback) as T;
  const [val, setVal] = useState(valid.includes(init) ? init : fallback);
  const set = (v: T) => {
    setVal(v);
    qsSet(key, v);
  };
  return [val, set];
}

// --- page ---

export function AnalyticsPage({ ip, agents }: { ip?: string; agents: Agent[] }) {
  const deviceName = ip ? agents.find((a) => a.ip === ip)?.hostname || ip : undefined;
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [errorCount, setErrorCount] = useState(0);
  type Counts = Array<{ key: string; count: number }>;
  const [byDevice, setByDevice] = useState<Counts>([]);
  const [byHost, setByHost] = useState<Counts>([]);
  const [range, setRange] = useQS("range", "1h" as Range, RANGES);
  const [filterDevice, setFilterDevice] = useState<string | null>(null);
  const [filterHost, setFilterHost] = useState<string | null>(null);
  const isGlobal = !ip;
  const agentNames = useMemo(
    () => new Map(agents.map((a) => [a.ip, a.hostname || a.ip])),
    [agents],
  );

  // Skip setState (and thus the chart redraw) when the polled
  // response is identical to the last one — common on long ranges
  // where 24h of data barely shifts every 10 s.
  const lastSig = useRef("");
  useEffect(() => {
    lastSig.current = "";
    let cancelled = false;
    const load = () => {
      getAnalytics({ range, agent: ip, limit: 5000 })
        .then((r) => {
          if (cancelled) return;
          const first = r.events[0]?.id ?? "";
          const last = r.events[r.events.length - 1]?.id ?? "";
          const sig = `${r.total_count}|${r.error_count}|${r.events.length}|${first}|${last}`;
          if (sig === lastSig.current) return;
          lastSig.current = sig;
          setEvents(r.events);
          setTotalCount(r.total_count);
          setErrorCount(r.error_count);
          setByDevice(r.by_device ?? []);
          setByHost(r.by_host ?? []);
        })
        .catch(() => {});
    };
    load();
    // Auto-refresh only for short ranges. On 1h+ the data barely
    // shifts per poll and the redraw is mostly noise.
    if (RANGE_MS[range] >= 3600e3) {
      return () => {
        cancelled = true;
      };
    }
    const t = setInterval(load, 10000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, [ip, range]);

  // Client-side filters from bar chart clicks
  const filtered = useMemo(
    () =>
      events.filter((e) => {
        if (filterDevice && e.agent_ip !== filterDevice) return false;
        if (filterHost && e.host !== filterHost) return false;
        return true;
      }),
    [events, filterDevice, filterHost],
  );
  const hasFilter = filterDevice || filterHost;
  const filterLabel = filterDevice
    ? (agentNames.get(filterDevice) ?? filterDevice)
    : (filterHost ?? "");

  // --- summary stats ---
  // Counts (n, errPct) come from server-side aggregates so the
  // headline isn't capped at the 5000-row scatter sample. Avg / p99 /
  // devices are computed from the sample — statistically valid for
  // a uniform random draw and avoids extra SQL passes.
  const stats = (() => {
    const sampleN = filtered.length;
    if (sampleN === 0 && !hasFilter && totalCount === 0) {
      return { n: 0, avg: 0, p99: 0, errPct: 0, devices: 0 };
    }
    const lats = filtered
      .map((e) => e.ms)
      .filter((m) => m > 0)
      .sort((a, b) => a - b);
    const avg = lats.length ? Math.round(lats.reduce((a, b) => a + b, 0) / lats.length) : 0;
    const p99 = lats.length ? lats[Math.min(Math.floor(lats.length * 0.99), lats.length - 1)] : 0;
    const devices = new Set(filtered.map((e) => e.agent_ip).filter(Boolean)).size;
    if (hasFilter) {
      const errs = filtered.filter((e) => (e.status ?? 0) >= 400).length;
      const errPct = sampleN > 0 ? (errs / sampleN) * 100 : 0;
      return { n: sampleN, avg, p99, errPct, devices };
    }
    const errPct = totalCount > 0 ? (errorCount / totalCount) * 100 : 0;
    return { n: totalCount, avg, p99, errPct, devices };
  })();

  const trail: Crumb[] = [];
  if (deviceName) {
    trail.push({ label: "Devices", href: "#/devices" });
    trail.push({
      label: deviceName,
      href: `#/device/${encodeURIComponent(ip!)}`,
    });
  }
  trail.push({ label: "Analytics" });

  return (
    <Main>
      <PageTitle
        trail={trail}
        actions={
          <>
            {hasFilter && (
              <Tag
                tone="info"
                dismissible
                onClick={() => {
                  setFilterDevice(null);
                  setFilterHost(null);
                }}
                className="normal-case"
              >
                {filterLabel}
              </Tag>
            )}
            <Toggle options={[...RANGES]} value={range} onChange={setRange} />
          </>
        }
      />

      <div
        className={
          "bg-canvas border-1.5 border-navy grid grid-cols-2 divide-x divide-canvas-dark " +
          (isGlobal ? "sm:grid-cols-4 lg:grid-cols-5" : "sm:grid-cols-4")
        }
      >
        <Stat label="Requests" value={stats.n.toLocaleString()} />
        <Stat label="Avg" value={stats.avg ? fmtMs(stats.avg) : "—"} />
        <Stat label="p99" value={stats.p99 ? fmtMs(stats.p99) : "—"} />
        <Stat
          label="Errors"
          value={stats.errPct ? stats.errPct.toFixed(1) + "%" : "0%"}
          tone={stats.errPct >= 5 ? "warn" : undefined}
        />
        {isGlobal && <Stat label="Devices" value={stats.devices.toLocaleString()} />}
      </div>

      <div className={"grid gap-4 " + (isGlobal ? "grid-cols-1 md:grid-cols-2" : "grid-cols-1")}>
        {isGlobal && (
          <BarList
            title="Count by device"
            items={byDevice}
            active={filterDevice}
            labelFn={(v) => agentNames.get(v) ?? v}
            colorFn={(_, label) => deviceColor(label)}
            onClickFn={(v) => {
              setFilterDevice(filterDevice === v ? null : v);
              setFilterHost(null);
            }}
          />
        )}
        <BarList
          title="Count by host"
          items={byHost}
          active={filterHost}
          colorFn={(key) => hostColor(key)}
          onClickFn={(v) => {
            setFilterHost(filterHost === v ? null : v);
            setFilterDevice(null);
          }}
        />
      </div>

      <LatencyChart filtered={filtered} isGlobal={isGlobal} agents={agents} range={range} />

      <TopRoutes events={filtered} />
    </Main>
  );
}

function fmtMs(ms: number): string {
  if (ms >= 1000) return (ms / 1000).toFixed(1) + "s";
  return ms + "ms";
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: "warn" }) {
  return (
    <div className="flex flex-col gap-1.5 px-5 py-4">
      <span className="font-mono text-2xs uppercase tracking-wider text-text-subtle">{label}</span>
      <span
        className={
          "text-2xl font-semibold leading-none tabular-nums tracking-tight " +
          (tone === "warn" ? "text-danger-600" : "text-text")
        }
      >
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
    h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  }
  return ((h % n) + n) % n;
}

// 10 perceptually-distinct categorical chart hues. Intentionally
// outside the brand palette: rust + navy + butter only give us three
// anchors, but the host-color hash needs 10+ to avoid clashes in dense
// scatter plots. Charts are the one place we accept non-token colors.
const PALETTE = [
  "#2563eb", // blue-600
  "#dc2626", // red-600
  "#16a34a", // green-600
  "#ea580c", // orange-600
  "#9333ea", // purple-600
  "#0d9488", // teal-600
  "#ca8a04", // yellow-600
  "#db2777", // pink-600
  "#65a30d", // lime-600
  "#475569", // slate-600
];
const hostColor = (s: string) => PALETTE[stableIndex(s, PALETTE.length)];
// Offset by half the palette so the same string hashes to a maximally
// different hue when used as a device vs. a host.
const deviceColor = (s: string) => PALETTE[(stableIndex(s, PALETTE.length) + 5) % PALETTE.length];

// HTTP status families, mapped to the brand semantic tokens. Hex
// literals because Observable Plot serializes these directly into
// SVG fill attributes and can't resolve `var(--color-…)`. Keep in
// sync with --color-success / --color-butter / --color-rust /
// --color-danger / --color-text-subtle in index.css.
const STATUS_COLORS = {
  "2xx": "#4a6f30", // success-600
  "3xx": "#a47208", // butter-700
  "4xx": "#b6420f", // rust-600
  "5xx": "#8d2424", // danger-600
  "—": "#82838c", // text-subtle
} as const;

// --- chart ---

function LatencyChart({
  filtered,
  isGlobal,
  agents,
  range,
}: {
  filtered: EventRecord[];
  isGlobal: boolean;
  agents: Agent[];
  range: Range;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const colorOptions: ColorBy[] = isGlobal ? ["device", "host", "status"] : ["host", "status"];
  const [colorBy, setColorBy] = useQS("color", colorOptions[0], colorOptions);
  const [scale, setScale] = useQS("scale", "log" as Scale, ["log", "linear"]);

  const agentNames = useMemo(
    () => new Map(agents.map((a) => [a.ip, a.hostname || a.ip])),
    [agents],
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
          ? e.status >= 500
            ? "5xx"
            : e.status >= 400
              ? "4xx"
              : e.status >= 300
                ? "3xx"
                : "2xx"
          : "\u2014",
      }));

    const colorField = colorBy === "status" ? "status" : colorBy === "device" ? "device" : "host";

    const vals = [...new Set(dots.map((d) => d[colorField] as string))];

    const colorCfg =
      colorBy === "status"
        ? {
            domain: ["2xx", "3xx", "4xx", "5xx", "\u2014"],
            range: [
              STATUS_COLORS["2xx"],
              STATUS_COLORS["3xx"],
              STATUS_COLORS["4xx"],
              STATUS_COLORS["5xx"],
              STATUS_COLORS["\u2014"],
            ],
            legend: true,
          }
        : {
            domain: vals,
            range: vals.map((v) => (colorBy === "device" ? deviceColor(v) : hostColor(v))),
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
        color: "var(--color-text-muted)",
      },
      y: {
        type: scale,
        label: null,
        grid: true,
        nice: true,
        ...(scale === "log"
          ? {
              ticks: [1, 10, 100, 1000, 10000],
              tickFormat: (v: number) => (v >= 1000 ? `${v / 1000}k` : `${v}`),
            }
          : {
              domain: [0, Math.max(100, ...dots.map((d) => d.ms)) * 1.1],
            }),
      },
      x: {
        type: "time",
        label: null,
        domain: [new Date(Date.now() - RANGE_MS[range]), new Date()],
      },
      color: colorCfg,
      marks: [
        // Soft grid: redraw with very light stroke (Plot's default
        // grid is too dark against the muted palette).
        Plot.gridY({ stroke: "var(--color-canvas-dark)", strokeWidth: 1 }),
        Plot.gridX({ stroke: "var(--color-canvas-muted)", strokeWidth: 1 }),
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
          href: (d: (typeof dots)[0]) => (d.id ? `#/request/${d.id}` : undefined),
          title: (d: (typeof dots)[0]) =>
            `${d.host}\n${d.device}\n${d.statusCode || "\u2014"} \u2022 ${d.ms}ms`,
        }),
        Plot.tip(
          dots,
          Plot.pointer({
            x: "t",
            y: "ms",
            title: (d: (typeof dots)[0]) =>
              `${d.host}\n${d.device}\n${d.statusCode || "\u2014"} \u2022 ${d.ms}ms`,
          }),
        ),
      ],
    });

    // SVG <a> elements use xlink:href and do full
    // navigation — intercept clicks so the hash router
    // handles them instead.
    chart.addEventListener("click", (evt) => {
      const a = (evt.target as Element).closest("a");
      const href =
        a?.getAttribute("href") ?? a?.getAttributeNS("http://www.w3.org/1999/xlink", "href");
      if (href?.startsWith("#/request/")) {
        evt.preventDefault();
        window.location.hash = href;
      }
    });
    chart.querySelectorAll("a").forEach((a) => {
      (a as unknown as HTMLElement).style.cursor = "pointer";
    });

    // Hover-to-highlight: dim dots whose `fill` doesn't match the
    // swatch's `fill`. Plot's swatch DOM is `<span class="*-swatch">`
    // with an inner `<svg fill="...">` and the value as a text node —
    // there are no aria-labels, so we read the color straight off the
    // swatch's SVG (same scale as the dots use).
    const dotEls = chart.querySelectorAll<SVGCircleElement>("g[aria-label='dot'] circle");
    const setHighlight = (target: string | null) => {
      if (!target) {
        dotEls.forEach((c) => {
          c.style.opacity = "";
        });
        return;
      }
      dotEls.forEach((c) => {
        c.style.opacity = c.getAttribute("fill") === target ? "1" : "0.08";
      });
    };

    const nameToIP =
      colorBy === "device" ? new Map(agents.map((a) => [a.hostname || a.ip, a.ip])) : null;

    chart
      .querySelectorAll<HTMLElement>("[class*='-swatch']:not([class*='-swatches'])")
      .forEach((el) => {
        const color = el.querySelector("svg")?.getAttribute("fill") ?? null;
        const label = el.textContent?.trim() ?? "";
        el.addEventListener("mouseenter", () => setHighlight(color));
        el.addEventListener("mouseleave", () => setHighlight(null));
        if (nameToIP) {
          const devIP = nameToIP.get(label);
          if (!devIP) return;
          el.style.cursor = "pointer";
          el.addEventListener("click", (e) => {
            e.stopPropagation();
            window.location.hash = `#/analytics/${encodeURIComponent(devIP)}`;
          });
        }
      });

    ref.current.replaceChildren(chart);
    return () => chart.remove();
  }, [filtered, colorBy, scale, range, agents, agentNames]);

  return (
    <section className="bg-canvas border-1.5 border-navy overflow-hidden">
      <header className="flex items-center justify-between px-4 py-2.5 bg-navy-100 border-b border-navy">
        <span className="text-xs font-mono uppercase tracking-wider font-bold text-navy">
          Latency
        </span>
        <div className="flex items-center gap-3">
          <Toggle options={colorOptions} value={colorBy} onChange={setColorBy} />
          <Toggle options={["log", "linear"] as Scale[]} value={scale} onChange={setScale} />
        </div>
      </header>
      <div ref={ref} className="p-4 min-h-80" />
    </section>
  );
}

// --- toggle ---

function Toggle<T extends string>({
  options,
  value,
  onChange,
}: {
  options: T[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div className="flex text-2xs border-1.5 border-navy squircle-sm overflow-hidden">
      {options.map((o) => (
        <button
          key={o}
          onClick={() => onChange(o)}
          className={
            "px-2 py-0.5 " +
            (o === value ? "bg-navy text-canvas" : "bg-canvas text-text-muted hover:bg-navy-100")
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
  p99Ms: number;
};

function TopRoutes({ events }: { events: EventRecord[] }) {
  const [sortBy, setSortBy] = useState<"count" | "p99Ms">("count");

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
    const p99i = Math.floor(sorted.length * 0.99);
    rows.push({
      key: k,
      method,
      host,
      path,
      count: sorted.length,
      p99Ms: sorted[Math.min(p99i, sorted.length - 1)],
    });
  }

  rows.sort((a, b) => b[sortBy] - a[sortBy]);
  const maxCount = rows.length ? rows[0].count : 0;

  const hdr = (label: string, field: "count" | "p99Ms") => (
    <th
      className="px-3 sm:px-3.5 py-2.5 text-right text-xs font-mono font-bold uppercase tracking-wider text-navy cursor-pointer hover:text-navy-700 select-none"
      onClick={() => setSortBy(field)}
    >
      {label}
      {sortBy === field ? " \u25BE" : ""}
    </th>
  );

  return (
    <section className="bg-canvas border-1.5 border-navy overflow-hidden">
      <table className="w-full text-xs">
        <colgroup>
          <col />
          <col className="w-30" />
          <col className="w-20" />
        </colgroup>
        <thead className="bg-navy-100 border-b border-navy">
          <tr>
            <th className="px-3 sm:px-3.5 py-2.5 text-left text-xs font-mono uppercase tracking-wider text-navy font-bold">
              Top routes
            </th>
            {hdr("Reqs", "count")}
            {hdr("p99", "p99Ms")}
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 20).map((d) => {
            const pct = maxCount > 0 ? (d.count / maxCount) * 100 : 0;
            return (
              <tr
                key={d.key}
                className="border-b border-canvas-muted hover:bg-canvas-muted transition-colors"
              >
                <td
                  className="px-3 sm:px-3.5 py-2.5 font-mono align-middle break-all"
                  title={`${d.method} ${d.host}${d.path}`}
                >
                  <span className="text-text-subtle">{d.method}</span> {d.host}
                  <span className="text-text-muted">{d.path}</span>
                </td>
                <td className="px-3 sm:px-3.5 py-2.5 text-right whitespace-nowrap align-middle">
                  <div className="flex items-center justify-end gap-1.5">
                    <div className="w-12 h-1.5 bg-canvas-muted rounded-full">
                      <div
                        className="h-full bg-text-subtle rounded-full"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <span className="w-8 text-right tabular-nums">{d.count}</span>
                  </div>
                </td>
                <td className="px-3 sm:px-3.5 py-2.5 text-right text-text-muted tabular-nums align-middle">
                  {fmtMs(d.p99Ms)}
                </td>
              </tr>
            );
          })}
          {rows.length === 0 && (
            <tr>
              <td colSpan={3} className="px-1 py-6 text-center text-xs text-text-subtle">
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

function BarList({
  title,
  items: rawItems,
  active,
  labelFn,
  onClickFn,
  colorFn,
}: {
  title: string;
  items: Array<{ key: string; count: number }>;
  active?: string | null;
  labelFn?: (v: string) => string;
  onClickFn?: (v: string) => void;
  colorFn?: (key: string, label: string) => string;
}) {
  const items = rawItems.map((it) => ({
    key: it.key,
    label: labelFn ? labelFn(it.key) : it.key,
    value: it.count,
  }));
  const max = items.length ? items[0].value : 0;

  return (
    <section className="bg-canvas border-1.5 border-navy overflow-hidden">
      <header className="px-4 py-2.5 bg-navy-100 border-b border-navy">
        <span className="text-xs font-mono uppercase tracking-wider font-bold text-navy">
          {title}
        </span>
      </header>
      <div className="p-3 space-y-0.5">
        {items.slice(0, 10).map((item) => {
          const pct = max > 0 ? (item.value / max) * 100 : 0;
          const isActive = active === item.key;
          // Non-colorFn fallback: brand-neutral bar fill via token var
          // so the bar inherits any theme adjustment in index.css.
          const barColor = colorFn
            ? colorFn(item.key, item.label)
            : isActive
              ? "var(--color-text)"
              : "var(--color-text-muted)";
          return (
            <div
              key={item.key}
              className={
                "flex items-center gap-2 px-1 py-0.5 rounded cursor-pointer " +
                (isActive ? "bg-navy-50" : "hover:bg-canvas-muted")
              }
              onClick={onClickFn ? () => onClickFn(item.key) : undefined}
            >
              <span
                className={
                  "w-32 truncate text-xs " +
                  (isActive ? "text-text font-semibold" : "text-text-muted")
                }
                title={item.label}
              >
                {item.label}
              </span>
              <div className="flex-1 h-2 bg-canvas-muted">
                <div
                  className="h-full"
                  style={{
                    width: `${pct}%`,
                    backgroundColor: barColor,
                    opacity: isActive ? 1 : 0.85,
                  }}
                />
              </div>
              <span className="w-8 text-right text-xs text-text-subtle tabular-nums">
                {item.value}
              </span>
            </div>
          );
        })}
        {items.length === 0 && (
          <div className="py-4 text-center text-xs text-text-subtle">
            No data in this time range
          </div>
        )}
      </div>
    </section>
  );
}
