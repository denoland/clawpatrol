import { useEffect, useRef, useState } from "react";
import * as Plot from "@observablehq/plot";
import type { Agent, EventRecord } from "../lib/api";
import { LiveRequests } from "./LiveRequests";

const RANGES = [
  "1m", "5m", "15m", "30m", "1h", "6h", "24h",
] as const;
type Range = typeof RANGES[number];
type ColorBy = "host" | "status";
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
  ip: string;
  agents: Agent[];
}) {
  const deviceName =
    agents.find(a => a.ip === ip)?.hostname || ip;
  const [events, setEvents] = useState<EventRecord[]>([]);

  useEffect(() => {
    setEvents([]);
    const url = `/api/events?agent=${encodeURIComponent(ip)}`;
    const es = new EventSource(url);
    // rAF-batched render: SSE on a busy gateway fires dozens of
    // events/sec. setState per event = re-render per event. Coalesce
    // into one commit per browser frame (~16 ms).
    let pending: EventRecord[] = [];
    let raf = 0;
    const flush = () => {
      raf = 0;
      if (pending.length === 0) return;
      const batch = pending;
      pending = [];
      setEvents((prev) => [...batch.reverse(), ...prev].slice(0, 5000));
    };
    es.onmessage = (e) => {
      try {
        pending.push(JSON.parse(e.data) as EventRecord);
        if (raf === 0) raf = requestAnimationFrame(flush);
      } catch { /* ignore */ }
    };
    return () => {
      es.close();
      if (raf !== 0) cancelAnimationFrame(raf);
    };
  }, [ip]);

  return (
    <main className="flex-1 mx-auto w-full max-w-[1100px] px-4 sm:px-6 py-8 space-y-6">
      <nav className="text-[11px] text-[#a3a3a3] flex items-center gap-1.5">
        <a href="#/" className="hover:text-[#171717]">
          clawpatrol
        </a>
        <span>/</span>
        <a
          href={`#/device/${encodeURIComponent(ip)}`}
          className="hover:text-[#171717]"
        >
          {deviceName}
        </a>
        <span>/</span>
        <span className="text-[#525252]">analytics</span>
      </nav>
      <LatencyChart events={events} />
      <LiveRequests agentIP={ip} height="500px" />
    </main>
  );
}

// --- chart ---

function LatencyChart({ events }: {
  events: EventRecord[];
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [colorBy, setColorBy] =
    useQS("color", "host" as ColorBy, ["host", "status"]);
  const [scale, setScale] =
    useQS("scale", "log" as Scale, ["log", "linear"]);
  const [range, setRange] =
    useQS("range", "5m" as Range, RANGES);

  useEffect(() => {
    if (!ref.current || events.length === 0) return;

    const cutoff = Date.now() - RANGE_MS[range];
    const dots = events
      .filter((e) => e.ms > 0 && new Date(e.ts).getTime() >= cutoff)
      .map((e) => ({
        t: new Date(e.ts),
        ms: e.ms,
        host: e.host,
        id: e.id,
        statusCode: e.status ?? 0,
        status: e.status
          ? e.status >= 500 ? "5xx"
          : e.status >= 400 ? "4xx"
          : e.status >= 300 ? "3xx"
          : "2xx"
          : "\u2014",
      }));

    if (dots.length === 0) {
      ref.current.replaceChildren();
      return;
    }

    const statusColor = {
      domain: ["2xx", "3xx", "4xx", "5xx", "\u2014"],
      range: [
        "#16a34a", "#ca8a04", "#ea580c",
        "#dc2626", "#a3a3a3",
      ],
      legend: true,
    };

    const hosts = [...new Set(dots.map(d => d.host))];
    const PALETTE = [
      "#2563eb", "#16a34a", "#ea580c", "#7c3aed",
      "#0891b2", "#ca8a04", "#dc2626", "#4f46e5",
      "#059669", "#d97706", "#be185d", "#0d9488",
    ];
    const hostColor = {
      domain: hosts,
      range: hosts.map(
        (_, i) => PALETTE[i % PALETTE.length],
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
      },
      x: {
        type: "time",
        label: null,
        domain: [new Date(cutoff), new Date()],
      },
      color: colorBy === "status"
        ? statusColor : hostColor,
      marks: [
        Plot.dot(dots, {
          x: "t",
          y: "ms",
          fill: colorBy === "status" ? "status" : "host",
          r: 3,
          fillOpacity: 0.7,
          channels: {
            host: "host",
            statusCode: "statusCode",
            id: "id",
          },
        }),
        Plot.tip(dots, Plot.pointer({
          x: "t",
          y: "ms",
          title: (d: typeof dots[0]) =>
            `${d.host}\n${d.statusCode || "\u2014"} \u2022 ${d.ms}ms`,
        })),
        Plot.ruleY([0]),
      ],
    });

    chart.addEventListener("click", (evt) => {
      const el = evt.target as SVGElement;
      const circle = el.closest("circle");
      if (!circle) return;
      const i = (circle as any).__data__;
      if (typeof i === "number" && dots[i]?.id) {
        window.location.hash =
          `#/request/${dots[i].id}`;
      }
    });
    chart.querySelectorAll("circle").forEach((c) => {
      (c as SVGElement).style.cursor = "pointer";
    });

    ref.current.replaceChildren(chart);
    return () => chart.remove();
  }, [events, colorBy, scale, range]);

  return (
    <div className="bg-white border border-[#e5e5e5] rounded overflow-hidden">
      <div className="px-4 py-2.5 border-b border-[#e5e5e5] flex items-center justify-between">
        <span className="text-[10px] uppercase tracking-[.12em] text-[#a3a3a3]">
          Latency
        </span>
        <div className="flex items-center gap-4">
          <Toggle
            options={[...RANGES]}
            value={range}
            onChange={setRange}
          />
          <Toggle
            options={["host", "status"] as ColorBy[]}
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
      <div ref={ref} className="p-4 min-h-[320px]">
        {events.length === 0 && (
          <div className="flex items-center justify-center h-[280px] text-[11px] text-[#a3a3a3]">
            Collecting data...
          </div>
        )}
      </div>
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
