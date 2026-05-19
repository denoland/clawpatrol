// Devices table — flat per-device summary. Click row → device page.

import { useEffect, useRef, useState } from "react";
import { type Agent, type EventRecord, type Integration } from "../lib/api";
import { fmtAge, fmtBytes } from "../lib/format";
import { DeviceIcon } from "./Logos";
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
  for (const i of integrations ?? []) byId.set(i.id, i);
  const stable = [...(agents ?? [])].sort((a, b) => a.ip.localeCompare(b.ip));
  const lastByIp = useLastActionByIp();
  return (
    <table className="w-full table-fixed border-collapse" style={{ minWidth: 720 }}>
      <colgroup>
        <col style={{ width: 220 }} />
        <col style={{ width: 130 }} />
        <col />
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
                <DeviceStatusCell needs={needs} lastAction={lastByIp.get(a.ip)} />
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
//   B — every credential is connected: green dot + the device's most
//       recent action (method · endpoint/host · path · age). The dot
//       briefly pulses when a fresh action lands; reuses the same
//       /api/events SSE feed LiveRequests subscribes to.
function DeviceStatusCell({
  needs,
  lastAction,
}: {
  needs: string[];
  lastAction: EventRecord | undefined;
}) {
  if (needs.length > 0) {
    return (
      <a
        href="#/settings"
        onClick={(e) => e.stopPropagation()}
        title={`needs setup: ${needs.join(", ")}`}
        className="text-xs text-rust-700 hover:text-rust-800 hover:underline"
      >
        {needs.length} credential{needs.length === 1 ? "" : "s"} not connected. Click to configure
      </a>
    );
  }
  return (
    <span className="inline-flex items-center gap-2 text-xs min-w-0">
      <LiveDot pulseKey={lastAction ? (lastAction.id ?? "") + lastAction.ts : "idle"} />
      {lastAction ? (
        <>
          <span className="font-mono text-text-muted shrink-0">{lastAction.method || "—"}</span>
          <span className="truncate" title={lastActionTitle(lastAction)}>
            <span className="text-text-muted">{lastAction.endpoint || lastAction.host}</span>
            {lastAction.path && <span>{lastAction.path}</span>}
          </span>
          <span className="text-text-subtle shrink-0">{fmtAge(lastAction.ts)}</span>
        </>
      ) : (
        <span className="text-text-muted">connected · no actions yet</span>
      )}
    </span>
  );
}

function lastActionTitle(ev: EventRecord): string {
  return [ev.method, ev.endpoint || ev.host, ev.path].filter(Boolean).join(" ");
}

// LiveDot — green dot that briefly pulses when `pulseKey` changes,
// signalling a fresh action on the row. Held for ~1.2s so a burst
// of events doesn't strobe the row.
function LiveDot({ pulseKey }: { pulseKey: string }) {
  const [pulse, setPulse] = useState(false);
  const t = useRef<number | null>(null);
  useEffect(() => {
    setPulse(true);
    if (t.current) clearTimeout(t.current);
    t.current = window.setTimeout(() => setPulse(false), 1200);
    return () => {
      if (t.current) clearTimeout(t.current);
    };
  }, [pulseKey]);
  return (
    <span
      className={
        "shrink-0 w-[5px] h-[5px] rounded-full bg-success-500" + (pulse ? " animate-pulse" : "")
      }
      aria-label="all credentials connected"
    />
  );
}

// useLastActionByIp subscribes to /api/events and tracks the most
// recent completed action per agent IP. Frames and `start` phases are
// skipped so the row only updates on `end` events. Batched via
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
          if (ev.phase === "frame" || ev.phase === "start") continue;
          const ip = ev.agent_ip;
          if (!ip) continue;
          const existing = next.get(ip);
          if (!existing || (ev.ts ?? "") > (existing.ts ?? "")) {
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
