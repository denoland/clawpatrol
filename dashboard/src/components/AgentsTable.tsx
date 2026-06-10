// Devices table — flat per-device summary. Click row → device page.

import type { Agent, Integration } from "../lib/api";
import { fmtBytes } from "../lib/format";
import { DeviceIcon } from "./Logos";
import { Sparkline } from "./Sparkline";

export function AgentsTable({
  agents,
  integrations,
  onSelect,
  sortBy = "ip",
}: {
  agents: Agent[];
  integrations?: Integration[];
  onSelect?: (ip: string) => void;
  // "ip": ascending IP — stable, default.
  // "activity": most-recently-active first, bucketed to the hour so
  // ordering doesn't reshuffle on every ping. IP tiebreak.
  sortBy?: "ip" | "activity";
}) {
  const byId = new Map<string, Integration>();
  for (const i of integrations ?? []) byId.set(i.id, i);
  const stable = sortAgents(agents ?? [], sortBy);
  return (
    <table className="w-full table-fixed border-collapse" style={{ minWidth: 720 }}>
      <colgroup>
        <col />
        <col style={{ width: 140 }} />
        <col style={{ width: 200 }} />
        <col style={{ width: 70 }} />
        <col style={{ width: 200 }} />
      </colgroup>
      <thead className="bg-navy-100 border-b border-navy">
        <tr>
          <Th>Device</Th>
          <Th>Profile</Th>
          <Th>Activity</Th>
          <Th className="text-right">Reqs</Th>
          <Th>IP</Th>
        </tr>
      </thead>
      <tbody>
        {stable.length === 0 && (
          <tr>
            <td colSpan={5} className="px-5 py-8 text-center text-xs text-text-subtle">
              It's empty in here
            </td>
          </tr>
        )}
        {stable.map((a) => {
          const total = a.bytes_in + a.bytes_out;
          const needs = (a.integrations ?? []).filter((id) => needsAction(byId.get(id)));
          const flagged = needs.length > 0;
          const dotTitle = flagged
            ? `${needs.length} integration${needs.length === 1 ? "" : "s"} need setup: ${needs.join(", ")}`
            : "";
          // Placeholder rows for devices approved but not yet connected
          // (the gateway keys them "tsnet-<host>" until first register).
          const pending = a.ip.startsWith("tsnet-");
          return (
            <tr
              key={a.ip}
              onClick={() => onSelect?.(a.ip)}
              className={
                "border-b border-canvas-muted cursor-pointer hover:bg-canvas-muted transition-colors " +
                // Dim pending rows as a cue, but keep them clickable —
                // the detail page is where the operator re-assigns the
                // profile before the device first connects.
                (pending ? "opacity-70" : "")
              }
            >
              <Td>
                <div className="flex items-center gap-1.5 min-w-0">
                  <span
                    title={dotTitle}
                    className={
                      "w-[5px] h-[5px] rounded-full shrink-0 " +
                      (flagged ? "bg-danger-500" : "bg-success-500")
                    }
                  />
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
              </Td>
              <Td className="text-xs text-text-muted truncate">{a.profile || "—"}</Td>
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
                className="text-xs text-text-muted tabular-nums truncate"
                title={
                  [a.external_ipv4, a.external_ipv6].filter(Boolean).join(" / ") ||
                  (pending ? "approved, waiting for first connect" : `wg ${a.ip}`)
                }
              >
                {a.external_ipv4 || a.external_ipv6 || (pending ? "pending first connect" : a.ip)}
              </Td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

const HOUR_MS = 60 * 60 * 1000;

export function sortAgents(agents: Agent[], by: "ip" | "activity"): Agent[] {
  const out = [...agents];
  if (by === "ip") {
    out.sort((a, b) => a.ip.localeCompare(b.ip));
    return out;
  }
  out.sort((a, b) => {
    const ba = Math.floor((Date.parse(a.last_at) || 0) / HOUR_MS);
    const bb = Math.floor((Date.parse(b.last_at) || 0) / HOUR_MS);
    if (ba !== bb) return bb - ba;
    return a.ip.localeCompare(b.ip);
  });
  return out;
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
        "px-3 sm:px-3.5 py-2.5 text-left text-xs font-mono uppercase tracking-wider text-navy font-bold " +
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
    <td className={"px-3 sm:px-3.5 py-2.5 align-middle overflow-hidden " + className} {...rest}>
      {children}
    </td>
  );
}
