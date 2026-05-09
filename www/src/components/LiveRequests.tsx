import { useEffect, useState } from "react";
import { type EventRecord } from "../lib/api";

type RowState = EventRecord & { frames?: { direction: string; frame: string; ts: string }[] };

export function LiveRequests({
  agentIP,
  max = 200,
  height,
}: {
  agentIP?: string;
  max?: number;
  height?: string;
}) {
  const [events, setEvents] = useState<RowState[]>([]);

  useEffect(() => {
    setEvents([]);
    const url = agentIP ? `/api/events?agent=${encodeURIComponent(agentIP)}` : "/api/events";
    const es = new EventSource(url);

    // Batched render: SSE can fire dozens of events per second on a
    // busy gateway (start + frame + end per request). setState every
    // event = a re-render every event = jank. Buffer parsed events
    // into pending[] and flush via requestAnimationFrame; the React
    // commit happens at most once per browser frame (~16 ms) no
    // matter how many events arrived in between.
    let pending: EventRecord[] = [];
    let raf = 0;
    const flush = () => {
      raf = 0;
      if (pending.length === 0) return;
      const batch = pending;
      pending = [];
      setEvents((prev) => {
        let next = prev;
        for (const ev of batch) next = mergeEvent(next, ev, max);
        return next;
      });
    };
    // Backlog ships as one event up front: bulk-insert in a single
    // commit so old events appear instantly instead of streaming in
    // through the live render path and looking like fresh activity.
    es.addEventListener("backlog", (e) => {
      try {
        const arr = JSON.parse((e as MessageEvent).data) as EventRecord[];
        setEvents((prev) => {
          let next = prev;
          for (const ev of arr) next = mergeEvent(next, ev, max);
          return next;
        });
      } catch {
        /* ignore */
      }
    });
    es.onmessage = (e) => {
      try {
        pending.push(JSON.parse(e.data) as EventRecord);
        if (raf === 0) raf = requestAnimationFrame(flush);
      } catch {
        /* ignore */
      }
    };
    return () => {
      es.close();
      if (raf !== 0) cancelAnimationFrame(raf);
    };
  }, [agentIP, max]);

  return (
    <div
      className="flex flex-col bg-white border border-[#e5e5e5] rounded overflow-hidden"
      style={{ height: height ?? "420px" }}
    >
      <div className="flex items-center px-4 py-2.5 text-[10px] uppercase tracking-[.12em] text-[#a3a3a3] border-b border-[#e5e5e5] flex-shrink-0">
        <span>LIVE REQUESTS</span>
        <span className="ml-2 text-[#22c55e] tabular-nums flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-[#22c55e] animate-pulse" />
          {events.length}
        </span>
      </div>
      <div className="flex-1 overflow-y-auto">
        {events.length === 0 ? (
          <div className="px-5 py-8 text-center text-[11px] text-[#a3a3a3] flex items-center justify-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#22c55e] animate-pulse" />
            Waiting for requests
            <AnimatedDots />
          </div>
        ) : (
          events.map((e, i) => <Row key={i} ev={e} />)
        )}
      </div>
    </div>
  );
}

// mergeEvent applies a new SSE event to the row list:
//   - phase="start" with id  → prepend in-flight row, dedupe by id.
//   - phase="end" with id    → replace the matching in-flight row in
//                              place so its visual position doesn't
//                              jump (preserve any accumulated WS frames).
//   - phase="frame" with id  → append a frame to the matching row's
//                              `frames` list, no row reorder.
//   - phase undefined / no id → legacy/non-correlated event, prepend.
function mergeEvent(prev: RowState[], ev: EventRecord, max: number): RowState[] {
  if (ev.id && ev.phase === "frame") {
    return prev.map((r) =>
      r.id === ev.id
        ? {
            ...r,
            frames: [
              ...(r.frames ?? []),
              { direction: ev.direction ?? "", frame: ev.frame ?? "", ts: ev.ts },
            ],
          }
        : r,
    );
  }
  if (ev.id && ev.phase === "end") {
    let found = false;
    const next = prev.map((r) => {
      if (r.id !== ev.id) return r;
      found = true;
      return { ...ev, frames: r.frames };
    });
    if (found) return next;
    return [ev, ...prev].slice(0, max);
  }
  if (ev.id && ev.phase === "start") {
    if (prev.some((r) => r.id === ev.id)) return prev;
    return [ev, ...prev].slice(0, max);
  }
  return [ev, ...prev].slice(0, max);
}

// pathSeparator: HTTP paths start with "/", so they visually butt up
// against the host fine. SQL "paths" (`SELECT now()`) need a space so
// the row reads `66.42.120.196 SELECT now()` not `66.42.120.196SELECT`.
function pathSeparator(path: string): string {
  if (!path) return "";
  return path.startsWith("/") ? "" : " ";
}

function Row({ ev }: { ev: RowState }) {
  const onClick = ev.id
    ? () => {
        window.location.hash = `#/request/${ev.id}`;
      }
    : undefined;
  const t = new Date(ev.ts);
  const time =
    t.toLocaleTimeString([], { hour12: false }) +
    "." +
    String(t.getMilliseconds()).padStart(3, "0");
  const inFlight = ev.phase === "start";
  const status = ev.status || 0;
  const statusColor = inFlight
    ? "text-[#a3a3a3]"
    : status >= 500
      ? "text-[#dc2626]"
      : status >= 400
        ? "text-[#ea580c]"
        : status >= 300
          ? "text-[#ca8a04]"
          : status >= 200
            ? "text-[#16a34a]"
            : "text-[#737373]";
  const path = ev.path ?? "";
  const sep = pathSeparator(path);
  const hasFrames = (ev.frames?.length ?? 0) > 0;
  return (
    <div className="border-b border-[#f5f5f5]">
      <div
        onClick={onClick}
        className={
          "px-4 py-2 flex items-center gap-3 min-w-0 transition-colors" +
          (onClick ? " cursor-pointer" : "") +
          (inFlight ? " opacity-70" : "") +
          " hover:bg-[#f9f9f9]"
        }
      >
        <span className="text-[10px] tabular-nums text-[#a3a3a3] flex-shrink-0">{time}</span>
        <ModeIcon mode={ev.mode} />
        {ev.method && (
          <span className="text-[10px] uppercase font-semibold text-[#525252] flex-shrink-0 w-[44px]">
            {ev.method}
          </span>
        )}
        <span className={"text-[11px] tabular-nums flex-shrink-0 w-[36px] " + statusColor}>
          {inFlight ? <InFlightSpinner /> : status || "—"}
        </span>
        <span
          className="text-[12px] text-[#171717] truncate flex-1 min-w-0"
          title={ev.host + sep + path}
        >
          <span className="text-[#737373]">{ev.host}</span>
          {sep && <span> </span>}
          <span>{path}</span>
        </span>
        <span className="text-[10px] tabular-nums text-[#a3a3a3] flex-shrink-0">
          {inFlight ? "…" : ev.ms + "ms"}
        </span>
      </div>
      {hasFrames && (
        <div className="bg-[#fafafa] border-t border-[#f5f5f5] max-h-[180px] overflow-y-auto">
          {ev.frames!.map((f, i) => (
            <div key={i} className="px-4 py-1 flex items-start gap-2 text-[10px] font-mono">
              <span className="text-[#a3a3a3] flex-shrink-0 w-[24px]">{f.direction}</span>
              <span className="text-[#525252] truncate" title={f.frame}>
                {f.frame}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function InFlightSpinner() {
  return (
    <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#a3a3a3] animate-pulse align-middle" />
  );
}

// AnimatedDots: cycles "", ".", "..", "..." every 400ms so the empty
// state reads as actively waiting rather than stalled. Pure CSS would
// need monospace + width pinning to avoid layout shift; the JS version
// is small and the surrounding row only paints when the list is empty.
function AnimatedDots() {
  const [n, setN] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setN((x) => (x + 1) % 4), 400);
    return () => clearInterval(t);
  }, []);
  return <span className="inline-block w-3 text-left">{".".repeat(n)}</span>;
}

function ModeIcon({ mode }: { mode: string }) {
  if (mode === "mitm") {
    return (
      <span title="MITM — gateway decrypted, inspected, forwarded" className="flex-shrink-0">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="#f6821f">
          <path d="M7 10V7a5 5 0 0 1 10 0v3h1a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h1Zm2 0h6V7a3 3 0 1 0-6 0v3Z" />
        </svg>
      </span>
    );
  }
  return (
    <span title="Splice — gateway forwarded encrypted bytes untouched" className="flex-shrink-0">
      <svg
        width="14"
        height="14"
        viewBox="0 0 24 24"
        fill="none"
        stroke="#a3a3a3"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M5 12h14" />
        <path d="m13 6 6 6-6 6" />
      </svg>
    </span>
  );
}
