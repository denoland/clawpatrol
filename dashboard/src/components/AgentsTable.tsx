// Devices table — flat per-device summary. Click row → device page.

import { useEffect, useState } from "react";
import { type Agent, type EventRecord, type Integration } from "../lib/api";
import { fmtBytes } from "../lib/format";
import { DeviceIcon, IntegrationIcon } from "./Logos";
import { Sparkline } from "./Sparkline";

export function AgentsTable({
  agents,
  integrations,
  onSelect,
}: {
  agents: Agent[];
  integrations?: Integration[];
  onSelect?: (ip: string) => void;
}) {
  const byId = new Map<string, Integration>();
  const byEndpoint = new Map<string, Integration>();
  for (const i of integrations ?? []) {
    byId.set(i.id, i);
    for (const ep of i.endpoints ?? []) byEndpoint.set(ep, i);
  }
  const stable = [...(agents ?? [])].sort((a, b) => a.ip.localeCompare(b.ip));
  const lastByIp = useLastActionByIp();
  return (
    <table className="w-full table-fixed border-collapse" style={{ minWidth: 940 }}>
      <colgroup>
        <col style={{ width: 220 }} />
        <col style={{ width: 130 }} />
        <col style={{ width: 380 }} />
        <col style={{ width: 180 }} />
        <col style={{ width: 60 }} />
        <col style={{ width: 140 }} />
      </colgroup>
      <thead className="bg-navy-100 border-b border-navy">
        <tr>
          <Th>Device</Th>
          <Th className="hidden md:table-cell">Profile</Th>
          <Th>Status</Th>
          <Th>Activity</Th>
          <Th className="text-right">Reqs</Th>
          <Th className="hidden lg:table-cell">IP</Th>
        </tr>
      </thead>
      <tbody>
        {stable.length === 0 && (
          <tr>
            <td colSpan={6} className="px-5 py-8 text-center text-xs text-text-subtle">
              It's empty in here
            </td>
          </tr>
        )}
        {stable.map((a) => {
          const total = a.bytes_in + a.bytes_out;
          const needs = (a.integrations ?? []).filter((id) => needsAction(byId.get(id)));
          return (
            <tr
              key={a.ip}
              onClick={() => onSelect?.(a.ip)}
              className="border-b border-canvas-muted cursor-pointer hover:bg-navy-50 transition-colors"
            >
              <Td>
                <div className="flex items-center gap-1.5 min-w-0">
                  <DeviceIcon
                    os={a.os}
                    hostname={a.hostname}
                    ua={a.ua}
                    className="w-[13px] h-[13px] text-text-muted shrink-0"
                  />
                  <span className="text-sm font-semibold text-text truncate">
                    {a.hostname || a.ip}
                  </span>
                </div>
                <div className="md:hidden text-2xs text-text-subtle truncate mt-0.5">
                  {a.profile || "—"}
                </div>
              </Td>
              <Td className="hidden md:table-cell text-xs text-text-muted truncate">
                {a.profile || "—"}
              </Td>
              <Td>
                <DeviceStatusCell
                  needs={needs}
                  lastAction={lastByIp.get(a.ip)}
                  byEndpoint={byEndpoint}
                />
              </Td>
              <Td>
                <div className="flex items-center gap-2">
                  <Sparkline data={a.activity} width={120} height={16} />
                  <span className="text-2xs text-text-muted tabular-nums whitespace-nowrap">
                    {fmtBytes(total)}
                  </span>
                </div>
              </Td>
              <Td className="text-xs text-text-muted tabular-nums text-right">{a.reqs}</Td>
              <Td
                className="hidden lg:table-cell text-xs text-text-muted tabular-nums truncate"
                title={
                  [a.external_ipv4, a.external_ipv6].filter(Boolean).join(" / ") || `wg ${a.ip}`
                }
              >
                {a.external_ipv4 || a.external_ipv6 || a.ip}
              </Td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// DeviceStatusCell renders one of two states per row:
//   A — at least one declared credential needs setup: a red link to
//       the Settings page so the operator can connect it in one
//       click. Click bubbles into the row's onSelect, so we stop
//       propagation to keep the link's navigation intent intact.
//       Pinned with `whitespace-nowrap` so the call-to-action stays
//       on a single line; column width keeps it visible.
//   B — every credential is connected: state-of-action logo +
//       endpoint-credential logo + method · endpoint/host · path.
//       The action body truncates with ellipsis when long; the two
//       leading logos are pinned. Reuses the /api/events SSE feed.
function DeviceStatusCell({
  needs,
  lastAction,
  byEndpoint,
}: {
  needs: string[];
  lastAction: EventRecord | undefined;
  byEndpoint: Map<string, Integration>;
}) {
  if (needs.length > 0) {
    return (
      <a
        href="#/settings"
        onClick={(e) => e.stopPropagation()}
        title={`needs setup: ${needs.join(", ")}`}
        className="text-xs text-rust-700 hover:text-rust-800 hover:underline whitespace-nowrap"
      >
        {needs.length} credential{needs.length === 1 ? "" : "s"} not connected. Click to configure
      </a>
    );
  }
  const integration = lastAction?.endpoint ? byEndpoint.get(lastAction.endpoint) : undefined;
  return (
    <div className="flex items-center gap-2 text-xs min-w-0">
      <ActionStateIcon ev={lastAction} />
      <EndpointLogo integration={integration} fallbackTitle={lastAction?.endpoint} />
      {lastAction ? (
        <>
          <span className="font-mono text-text-muted shrink-0">{lastAction.method || "—"}</span>
          <span className="truncate min-w-0" title={lastActionTitle(lastAction)}>
            <span className="text-text-muted">{lastAction.endpoint || lastAction.host}</span>
            {lastAction.path && <span>{lastAction.path}</span>}
          </span>
        </>
      ) : (
        <span className="text-text-muted truncate">connected · no actions yet</span>
      )}
    </div>
  );
}

function lastActionTitle(ev: EventRecord): string {
  return [ev.method, ev.endpoint || ev.host, ev.path].filter(Boolean).join(" ");
}

// EndpointLogo — small brand icon for the credential bound to the
// endpoint that processed the request (Claude, OpenAI, Postgres, …).
// Falls back to a neutral globe glyph when the endpoint isn't bound
// to a credential (or no action has been seen yet on this row).
function EndpointLogo({
  integration,
  fallbackTitle,
}: {
  integration: Integration | undefined;
  fallbackTitle?: string;
}) {
  if (integration) {
    return (
      <span className="shrink-0 inline-flex" title={integration.name}>
        <IntegrationIcon
          id={integration.id}
          type={integration.type}
          className="w-[13px] h-[13px]"
        />
      </span>
    );
  }
  return <GlobeGlyph className="w-[13px] h-[13px] text-text-subtle" title={fallbackTitle} />;
}

// ActionStateIcon — small logo that conveys where the most recent
// action sits in its lifecycle. Derived from `phase`, `action` and
// `status` on the SSE event so the row updates without extra fetches:
//   parsing            — start event in flight (request just arrived)
//   awaiting verdict   — async approver waiting on a human / llm
//   request forwarded  — terminal but no upstream status (streaming
//                        cut, client disconnect, upstream error)
//   response forwarded — terminal with an upstream status code
//   denied             — rule or approver returned a deny verdict
// No idle state: when the row has never seen an action we still
// show the parsing glyph so the cell stays visually anchored.
type ActionState =
  | "idle"
  | "parsing"
  | "awaiting_verdict"
  | "request_forwarded"
  | "response_forwarded"
  | "denied";

function classifyAction(ev: EventRecord | undefined): ActionState {
  if (!ev) return "idle";
  if (ev.phase === "start") return "parsing";
  const a = ev.action || "";
  if (a === "hitl_async_pending") return "awaiting_verdict";
  if (a === "deny" || a === "denied" || a === "hitl_deny" || a === "hitl_retry_rejected") {
    return "denied";
  }
  if (ev.status && ev.status > 0) return "response_forwarded";
  return "request_forwarded";
}

function ActionStateIcon({ ev }: { ev: EventRecord | undefined }) {
  const state = classifyAction(ev);
  const className = "shrink-0 w-[13px] h-[13px]";
  switch (state) {
    case "idle":
    case "parsing":
      return <ParsingGlyph className={className + " text-text-subtle"} />;
    case "awaiting_verdict":
      return <AwaitingGlyph className={className + " text-butter-600"} />;
    case "request_forwarded":
      return <RequestForwardedGlyph className={className + " text-text-muted"} />;
    case "response_forwarded":
      return <ResponseForwardedGlyph className={className + " text-success-600"} />;
    case "denied":
      return <DeniedGlyph className={className + " text-danger-500"} />;
  }
}

// ── state glyphs ─────────────────────────────────────────────────
// Each glyph is a 24×24 stroke icon styled with currentColor so the
// caller picks the tone via Tailwind. Kept inline (rather than the
// iconify CDN) so the action state stays legible even when the page
// is loaded offline / behind a strict CSP.

type GlyphProps = { className?: string; title?: string };

function ParsingGlyph({ className = "", title }: GlyphProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-label={title ?? "parsing"}
    >
      <title>parsing</title>
      <circle cx="11" cy="11" r="6" />
      <path d="M20 20l-4-4" />
    </svg>
  );
}

function AwaitingGlyph({ className = "", title }: GlyphProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-label={title ?? "awaiting verdict"}
    >
      <title>awaiting verdict</title>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </svg>
  );
}

function RequestForwardedGlyph({ className = "", title }: GlyphProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-label={title ?? "request forwarded"}
    >
      <title>request forwarded</title>
      <path d="M4 12h14" />
      <path d="m13 6 6 6-6 6" />
    </svg>
  );
}

function ResponseForwardedGlyph({ className = "", title }: GlyphProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-label={title ?? "response forwarded"}
    >
      <title>response forwarded</title>
      <path d="M4 12l5 5L20 6" />
    </svg>
  );
}

function DeniedGlyph({ className = "", title }: GlyphProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-label={title ?? "denied"}
    >
      <title>denied</title>
      <circle cx="12" cy="12" r="9" />
      <path d="M8 8l8 8M16 8l-8 8" />
    </svg>
  );
}

function GlobeGlyph({ className = "", title }: GlyphProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-label={title ?? "endpoint"}
    >
      <title>{title ?? "endpoint"}</title>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18" />
      <path d="M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18z" />
    </svg>
  );
}

// useLastActionByIp subscribes to /api/events and tracks the most
// recent action per agent IP, surfacing both in-flight (`start`) and
// terminal (`end`) phases so the row's state icon can flip live from
// "parsing" → final outcome. `frame` events (WS payloads) are skipped
// — they don't represent a new action. Batched via
// requestAnimationFrame to keep busy gateways from triggering a
// React commit per event.
function useLastActionByIp(): Map<string, EventRecord> {
  const [lastByIp, setLastByIp] = useState<Map<string, EventRecord>>(new Map());
  useEffect(() => {
    const es = new EventSource("/api/events");
    let pending: EventRecord[] = [];
    let raf = 0;
    const apply = (batch: EventRecord[]) => {
      setLastByIp((prev) => {
        let changed = false;
        const next = new Map(prev);
        for (const ev of batch) {
          if (ev.phase === "frame") continue;
          const ip = ev.agent_ip;
          if (!ip) continue;
          const existing = next.get(ip);
          // Prefer the latest by ts; on a tie (start + end share ts
          // when emitted in the same millisecond) the terminal phase
          // wins so the row settles on the final state.
          if (
            !existing ||
            (ev.ts ?? "") > (existing.ts ?? "") ||
            ((ev.ts ?? "") === (existing.ts ?? "") &&
              existing.phase === "start" &&
              ev.phase !== "start")
          ) {
            next.set(ip, ev);
            changed = true;
          }
        }
        return changed ? next : prev;
      });
    };
    const flush = () => {
      raf = 0;
      if (pending.length === 0) return;
      const batch = pending;
      pending = [];
      apply(batch);
    };
    const onBacklog = (e: Event) => {
      try {
        const arr = JSON.parse((e as MessageEvent).data) as EventRecord[];
        apply(arr);
      } catch {
        /* ignore */
      }
    };
    es.addEventListener("backlog", onBacklog);
    es.onmessage = (e) => {
      try {
        pending.push(JSON.parse(e.data) as EventRecord);
        if (raf === 0) raf = requestAnimationFrame(flush);
      } catch {
        /* ignore */
      }
    };
    return () => {
      es.removeEventListener("backlog", onBacklog);
      es.close();
      if (raf !== 0) cancelAnimationFrame(raf);
    };
  }, []);
  return lastByIp;
}

// needsAction returns true when a declared credential is missing its
// secret (not connected) or its OAuth token has already expired.
// Credentials with no auth path (the rare "api key only" inert case)
// don't qualify — there's nothing actionable to do.
function needsAction(it: Integration | undefined): boolean {
  if (!it) return false;
  const hasAuthPath = !!(
    it.has_oauth ||
    it.has_tailscale_auth ||
    (it.slots && it.slots.length > 0)
  );
  if (!hasAuthPath) return false;
  const connected = it.connected || (it.tailscale_auth?.connected ?? false);
  if (!connected) return true;
  if (it.expires_at && it.expires_at * 1000 < Date.now()) return true;
  return false;
}

function Th({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <th
      className={
        "px-3 sm:px-[14px] py-[9px] text-left text-xs font-mono uppercase tracking-wider text-navy font-bold " +
        className
      }
    >
      {children}
    </th>
  );
}

function Td({
  children,
  className = "",
  ...rest
}: {
  children: React.ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <td
      className={"px-3 sm:px-[14px] py-[9px] align-middle overflow-hidden " + className}
      {...rest}
    >
      {children}
    </td>
  );
}
