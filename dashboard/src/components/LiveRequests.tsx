import { useEffect, useState } from "react";
import { type EventRecord, type FacetSchema } from "../lib/api";
import { formatFacetValue, useFacets } from "../lib/facets";
import { fmtTime } from "../lib/format";

type RowState = EventRecord & {
  frames?: { direction: string; frame: string; ts: string }[];
};

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
  const { byFamily } = useFacets();

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
      className="flex flex-col bg-canvas border-1.5 border-navy overflow-hidden"
      style={{ height: height ?? "420px" }}
    >
      <div className="flex items-center px-4 py-2.5 text-xs font-mono uppercase tracking-wider text-navy font-bold bg-navy-100 border-b border-navy shrink-0">
        <span>Live requests</span>
        <span className="ml-2 text-success-500 tabular-nums flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-success-500 animate-pulse" />
          {events.length}
        </span>
      </div>
      <div className="flex-1 overflow-y-auto">
        {events.length === 0 ? (
          <div className="px-5 py-8 text-center text-xs text-text-subtle flex items-center justify-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-success-500 animate-pulse" />
            Waiting for requests
            <AnimatedDots />
          </div>
        ) : (
          events.map((e, i) => (
            <Row key={i} ev={e} schema={e.family ? byFamily[e.family] : undefined} />
          ))
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
              {
                direction: ev.direction ?? "",
                frame: ev.frame ?? "",
                ts: ev.ts,
              },
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

// rowDescriptors picks the short labels shown per event:
//   - leading slot (HTTP verb / SQL verb / k8s verb / "" if unknown)
//   - trailing slot (path / SQL summary / k8s resource·name / "")
// Uses the facet schema when one is registered for ev.family so new
// protocol plugins drop in without dashboard edits; falls back to
// the legacy method/path stuffing when facets aren't populated
// (pre-migration rows / unknown families).
function rowDescriptors(
  ev: EventRecord,
  schema: FacetSchema | undefined,
): { verb: string; body: string } {
  const facets = ev.facets ?? {};
  if (schema && Object.keys(facets).length > 0) {
    // Convention shared by the built-in facets: the leading column
    // is either "method" (HTTPS) or "verb" (SQL / k8s); the rest of
    // the report fields render into the trailing body. The schema
    // controls how each value formats.
    const leadName =
      schema.report_fields.find((f) => f.name === "method")?.name ??
      schema.report_fields.find((f) => f.name === "verb")?.name ??
      "";
    const verbField = leadName ? schema.report_fields.find((f) => f.name === leadName) : undefined;
    const verb = verbField ? formatFacetValue(verbField.kind, facets[leadName]) : "";
    const bodyParts: string[] = [];
    for (const f of schema.report_fields) {
      if (f.name === leadName) continue;
      // Status is rendered in its own coloured slot below — don't
      // duplicate it in the body.
      if (f.name === "status") continue;
      const v = formatFacetValue(f.kind, facets[f.name]);
      if (v) bodyParts.push(v);
    }
    return { verb, body: bodyParts.join(" · ") };
  }
  // Legacy fallback for events without a facets payload — the
  // gateway still populates ev.method/ev.path for back-compat with
  // pre-migration consumers.
  return { verb: ev.method ?? "", body: ev.path ?? "" };
}

function Row({ ev, schema }: { ev: RowState; schema: FacetSchema | undefined }) {
  const onClick = ev.id
    ? () => {
        window.location.hash = `#/request/${ev.id}`;
      }
    : undefined;
  const time = fmtTime(ev.ts);
  const inFlight = ev.phase === "start";
  const status = ev.status || 0;
  const statusColor = inFlight
    ? "text-text-subtle"
    : status >= 500
      ? "text-danger-500"
      : status >= 400
        ? "text-rust-500"
        : status >= 300
          ? "text-butter-600"
          : status >= 200
            ? "text-success-600"
            : "text-text-muted";
  const { verb, body } = rowDescriptors(ev, schema);
  const sep = body && !body.startsWith("/") ? " " : "";
  const hasFrames = (ev.frames?.length ?? 0) > 0;
  return (
    <div className="border-b border-canvas-muted">
      <div
        onClick={onClick}
        className={
          "px-4 py-2 flex items-center gap-3 min-w-0 transition-colors" +
          (onClick ? " cursor-pointer" : "") +
          (inFlight ? " opacity-70" : "") +
          " hover:bg-canvas-muted"
        }
      >
        <span className="text-2xs tabular-nums text-text-subtle shrink-0">{time}</span>
        <ModeIcon mode={ev.mode} />
        {verb && (
          <span className="font-mono text-2xs uppercase font-semibold text-text-muted shrink-0 w-11">
            {verb}
          </span>
        )}
        <span className={"text-xs tabular-nums shrink-0 w-9 " + statusColor}>
          {inFlight ? <InFlightSpinner /> : status || "—"}
        </span>
        <span className="text-xs text-text truncate flex-1 min-w-0" title={ev.host + sep + body}>
          <span className="text-text-muted">{ev.host}</span>
          {sep && <span> </span>}
          <span>{body}</span>
        </span>
        <span className="text-2xs tabular-nums text-text-subtle shrink-0">
          {inFlight ? "…" : ev.ms + "ms"}
        </span>
      </div>
      {hasFrames && (
        <div className="bg-canvas-muted border-t border-canvas-muted max-h-45 overflow-y-auto">
          {ev.frames!.map((f, i) => (
            <div key={i} className="px-4 py-1 flex items-start gap-2 text-2xs font-mono">
              <span className="text-text-subtle shrink-0 w-6">{f.direction}</span>
              <span className="text-text-muted truncate" title={f.frame}>
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
    <span className="inline-block w-1.5 h-1.5 rounded-full bg-text-subtle animate-pulse align-middle" />
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
      <span
        title="MITM — gateway decrypted, inspected, forwarded"
        className="shrink-0 text-rust-400"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
          <path d="M7 10V7a5 5 0 0 1 10 0v3h1a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h1Zm2 0h6V7a3 3 0 1 0-6 0v3Z" />
        </svg>
      </span>
    );
  }
  return (
    <span
      title="Splice — gateway forwarded encrypted bytes untouched"
      className="shrink-0 text-text-subtle"
    >
      <svg
        width="14"
        height="14"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
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
