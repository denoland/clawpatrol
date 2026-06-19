import { useEffect, useState } from "react";
import { type EventRecord, type FacetSchema } from "../lib/api";
import { formatFacetValue, useFacets } from "../lib/facets";
import { fmtTime } from "../lib/format";

type RowState = EventRecord & {
  frames?: { direction: string; frame: string; ts: string }[];
};

function isDeniedAction(ev: EventRecord): boolean {
  return ev.action === "deny" || ev.action === "denied" || ev.action === "hitl_deny";
}

// A "quiet" dial is an allowed brokered-dial action — the gateway→upstream
// dial a plugin endpoint makes (e.g. an AWS call's dial to *.amazonaws.com).
// It carries no metadata, so it's hidden unless the operator opts in. A
// denied dial is a blocked egress and is never hidden.
function isQuietDial(ev: EventRecord): boolean {
  return ev.method === "dial" && !isDeniedAction(ev);
}

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
  // Allowed brokered "dial" actions are the plumbing behind a plugin
  // endpoint (an AWS API call's gateway→AWS dial); they carry no metadata
  // and just clutter the log, so hide them by default. Denied dials are a
  // real egress block and always show (isQuietDial excludes them).
  const [showDials, setShowDials] = useState(false);
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

  const hiddenDials = events.reduce((n, e) => n + (isQuietDial(e) ? 1 : 0), 0);
  const shown = showDials ? events : events.filter((e) => !isQuietDial(e));

  return (
    <div
      className="flex flex-col bg-canvas border-1.5 border-navy overflow-hidden"
      style={{ height: height ?? "420px" }}
    >
      <div className="flex items-center px-4 py-2.5 text-xs font-mono uppercase tracking-wider text-navy font-bold bg-navy-100 border-b border-navy shrink-0">
        <span>Live requests</span>
        <span className="ml-2 text-success-500 tabular-nums flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-success-500 animate-pulse" />
          {shown.length}
        </span>
        {hiddenDials > 0 && (
          <button
            type="button"
            onClick={() => setShowDials((v) => !v)}
            className="ml-auto normal-case tracking-normal font-normal text-2xs text-text-subtle hover:text-text-muted"
            title="Brokered upstream dials carry no metadata; hidden by default"
          >
            {showDials ? "hide" : "show"} {hiddenDials} dial{hiddenDials === 1 ? "" : "s"}
          </button>
        )}
      </div>
      <div className="flex-1 overflow-y-auto">
        {shown.length === 0 ? (
          <div className="px-5 py-8 text-center text-xs text-text-subtle flex items-center justify-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-success-500 animate-pulse" />
            Waiting for requests
            <AnimatedDots />
          </div>
        ) : (
          shown.map((e, i) => (
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
export function rowDescriptors(
  ev: EventRecord,
  schema: FacetSchema | undefined,
): { verb: string; body: string } {
  const facets = ev.facets ?? {};
  if (schema && Object.keys(facets).length > 0) {
    // The leading column (the "verb") is the field the facet marks as
    // `title` — e.g. an AWS plugin marks iam_action so the row reads
    // "s3:ListBucket" rather than "POST". Facets that declare no title
    // (the built-ins) fall back to the method/verb-named field. The rest
    // of the report fields render into the trailing body, except those
    // marked `detail_only` (kept for the per-action detail view).
    const lead =
      schema.report_fields.find((f) => f.title) ??
      schema.report_fields.find((f) => f.name === "method") ??
      schema.report_fields.find((f) => f.name === "verb");
    const verb = lead ? formatFacetValue(lead.kind, facets[lead.name]) : "";
    const bodyParts: string[] = [];
    for (const f of schema.report_fields) {
      if (lead && f.name === lead.name) continue;
      if (f.detail_only) continue;
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
  // "splice"/"relay" forward the bytes without inspecting them, so
  // there's no verb to show — surface a lock instead. Every other mode
  // (mitm HTTP, parsed SQL like "pg"/"clickhouse_native", k8s) is
  // inspected and shows its verb (empty if none was parsed).
  const inspected = ev.mode !== "splice" && ev.mode !== "relay";
  const hasFrames = (ev.frames?.length ?? 0) > 0;
  const isDenied = ev.action === "deny" || ev.action === "denied" || ev.action === "hitl_deny";
  const isApproved = ev.action === "approved" || ev.action === "hitl_allow";
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
        <ApprovalStatusIcon ev={ev} inFlight={inFlight} />
        <span className="font-mono text-2xs uppercase font-semibold text-text-muted shrink-0 w-11 flex items-center">
          {inspected ? verb : <LockGlyph />}
        </span>
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
      {inFlight && ev.action === "hitl_pending" && (
        <div className="px-4 pb-1.5 flex items-center gap-1.5 text-2xs font-mono text-butter-600">
          <span className="w-1.5 h-1.5 rounded-full bg-butter-400 animate-pulse shrink-0" />
          awaiting approval
        </div>
      )}
      {isDenied && (
        <div className="px-4 pb-1.5 flex items-center gap-1.5 text-2xs font-mono text-danger-600 min-w-0">
          <span className="w-1.5 h-1.5 rounded-full bg-danger-500 shrink-0" />
          <span className="font-semibold">denied</span>
          {ev.rule && <span className="text-danger-400 shrink-0">· {ev.rule}</span>}
          {ev.reason && <span className="text-text-subtle truncate">· {ev.reason}</span>}
        </div>
      )}
      {isApproved && ev.approver_by && (
        <div className="px-4 pb-1.5 flex items-center gap-1.5 text-2xs font-mono text-success-600">
          <span className="w-1.5 h-1.5 rounded-full bg-success-500 shrink-0" />
          approved by {ev.approver_by}
        </div>
      )}
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

// ApprovalStatusIcon renders the request's approval/policy outcome as
// a stoplight dot in the row's leading slot: green = allowed/approved,
// red = denied/error, amber (pulsing) = awaiting human approval, muted
// = in-flight/unknown. This slot previously showed MITM vs splice
// mode; the connection-visibility signal moved to the verb slot, which
// now shows a lock when the bytes weren't inspected.
export function ApprovalStatusIcon({ ev, inFlight }: { ev: EventRecord; inFlight: boolean }) {
  const a = ev.action ?? "";
  if (a === "hitl_pending")
    return <StatusDot cls="bg-butter-400 animate-pulse" title="awaiting approval" />;
  if (a === "deny" || a === "denied" || a === "hitl_deny")
    return <StatusDot cls="bg-danger-500" title="denied" />;
  if (a === "error") return <StatusDot cls="bg-danger-500" title="error" />;
  if (a === "approved" || a === "hitl_allow")
    return <StatusDot cls="bg-success-500" title="approved" />;
  if (a === "allow" || a === "passthrough")
    return <StatusDot cls="bg-success-500" title="allowed" />;
  if (inFlight) return <StatusDot cls="bg-text-subtle animate-pulse" title="in flight" />;
  return <StatusDot cls="bg-text-subtle" title={a || "—"} />;
}

function StatusDot({ cls, title }: { cls: string; title: string }) {
  return (
    <span title={title} className="shrink-0 flex items-center justify-center w-3.5">
      <span className={"w-2 h-2 rounded-full " + cls} />
    </span>
  );
}

// LockGlyph marks a connection the gateway passed through without
// inspecting (splice / relay), shown in the verb slot in place of a
// parsed method/verb — which only exists for inspected connections.
export function LockGlyph() {
  return (
    <span
      title="passed through — gateway did not inspect this connection"
      className="text-text-subtle"
    >
      <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor">
        <path d="M7 10V7a5 5 0 0 1 10 0v3h1a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h1Zm2 0h6V7a3 3 0 1 0-6 0v3Z" />
      </svg>
    </span>
  );
}
