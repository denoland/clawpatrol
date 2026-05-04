import { useEffect, useRef, useState } from "react";
import * as Plot from "@observablehq/plot";
import type { EventRecord } from "./LiveRequests";
import { LiveRequests } from "./LiveRequests";

export function AnalyticsPage({ ip, onBack }: {
  ip: string;
  onBack: () => void;
}) {
  const [events, setEvents] = useState<EventRecord[]>([]);

  useEffect(() => {
    setEvents([]);
    const url = `/api/events?agent=${encodeURIComponent(ip)}`;
    const es = new EventSource(url);
    es.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data) as EventRecord;
        setEvents((prev) => [ev, ...prev].slice(0, 2000));
      } catch { /* ignore */ }
    };
    return () => es.close();
  }, [ip]);

  return (
    <main className="flex-1 mx-auto w-full max-w-[1100px]
      px-4 sm:px-6 py-8 space-y-6">
      <div className="flex items-center gap-4">
        <button
          onClick={onBack}
          className="text-[#a3a3a3] hover:text-[#171717]
            transition-colors text-sm"
        >
          ← back
        </button>
        <h1 className="font-serif text-[28px] sm:text-[36px]
          leading-none tracking-tight text-[#171717]">
          {ip}
        </h1>
      </div>
      <LatencyChart events={events} />
      <LiveRequests agentIP={ip} height="500px" />
    </main>
  );
}

function LatencyChart({ events }: { events: EventRecord[] }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!ref.current || events.length === 0) return;

    const dots = events
      .filter((e) => e.ms > 0)
      .map((e) => ({
        t: new Date(e.ts),
        ms: e.ms,
        host: e.host,
        status: e.status
          ? e.status >= 500 ? "5xx"
          : e.status >= 400 ? "4xx"
          : e.status >= 300 ? "3xx"
          : "2xx"
          : "—",
      }));

    if (dots.length === 0) return;

    const chart = Plot.plot({
      width: ref.current.clientWidth,
      height: 280,
      marginLeft: 60,
      marginBottom: 40,
      y: {
        type: "log",
        label: "Latency (ms)",
        grid: true,
      },
      x: {
        type: "time",
        label: null,
      },
      color: {
        domain: ["2xx", "3xx", "4xx", "5xx", "—"],
        range: [
          "#16a34a", "#ca8a04", "#ea580c",
          "#dc2626", "#a3a3a3",
        ],
        legend: true,
      },
      marks: [
        Plot.dot(dots, {
          x: "t",
          y: "ms",
          fill: "status",
          r: 3,
          fillOpacity: 0.7,
          title: (d: typeof dots[0]) =>
            `${d.host}\n${d.ms}ms (${d.status})`,
        }),
        Plot.ruleY([0]),
      ],
    });

    ref.current.replaceChildren(chart);
    return () => chart.remove();
  }, [events]);

  return (
    <div className="bg-white border border-[#e5e5e5] rounded
      overflow-hidden">
      <div className="px-4 py-2.5 text-[10px] uppercase
        tracking-[.12em] text-[#a3a3a3] border-b
        border-[#e5e5e5]">
        Latency
      </div>
      <div ref={ref} className="p-4 min-h-[320px]">
        {events.length === 0 && (
          <div className="flex items-center justify-center
            h-[280px] text-[11px] text-[#a3a3a3]">
            Collecting data...
          </div>
        )}
      </div>
    </div>
  );
}
