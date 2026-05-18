import { useEffect, useMemo, useState } from "react";
import {
  type Agent,
  type EventRecord,
  getAnalytics,
  type HITLPending,
  type Integration,
} from "../../lib/api";
import { fmtAge, fmtDateTime } from "../../lib/format";
import { PageHeader } from "../cards/PageHeader";
import type { ReactNode } from "react";

// Overview — single-screen operator console. Three panels per the
// PR #398 spec:
//   row 1 (~75% vertical): [25%] recent activity • [75%] unconfigured credentials
//   row 2 (~25% vertical): pending approvals (full width)
// Fallbacks:
//   recent activity → list of connected devices when every declared
//     credential is connected (nothing to action there)
//   pending approvals → most recent rule verdicts when the HITL
//     queue is empty
export function OverviewPage({
  agents,
  integrations,
  pending,
}: {
  agents: Agent[];
  integrations: Integration[];
  pending: HITLPending[];
}) {
  const [events, setEvents] = useState<EventRecord[]>([]);

  useEffect(() => {
    let cancel = false;
    async function load() {
      try {
        const r = await getAnalytics({ range: "24h", limit: 100 });
        if (!cancel) setEvents(r.events ?? []);
      } catch {
        /* swallow */
      }
    }
    load();
    const id = setInterval(load, 10_000);
    return () => {
      cancel = true;
      clearInterval(id);
    };
  }, []);

  const unconfigured = useMemo(() => integrations.filter((i) => !i.connected), [integrations]);
  const allConnected = integrations.length > 0 && unconfigured.length === 0;

  const profileByIp = useMemo(() => {
    const m = new Map<string, string>();
    for (const a of agents) m.set(a.ip, a.profile ?? "");
    return m;
  }, [agents]);

  const hostnameByIp = useMemo(() => {
    const m = new Map<string, string>();
    for (const a of agents) m.set(a.ip, a.hostname || a.ip);
    return m;
  }, [agents]);

  return (
    <div className="mx-auto max-w-7xl flex flex-col h-[calc(100vh-220px)] min-h-[640px]">
      <PageHeader
        title="Overview"
        subhead="Recent activity, credentials that still need attention, and approvals waiting on a verdict."
      />
      <div className="flex-1 grid grid-rows-[3fr_1fr] gap-4 min-h-0">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 min-h-0">
          <div className="lg:col-span-1 min-h-0">
            {allConnected ? (
              <ConnectedDevicesPanel agents={agents} />
            ) : (
              <RecentActivityPanel
                events={events}
                hostnameByIp={hostnameByIp}
                profileByIp={profileByIp}
              />
            )}
          </div>
          <div className="lg:col-span-3 min-h-0">
            <UnconfiguredCredentialsPanel unconfigured={unconfigured} total={integrations.length} />
          </div>
        </div>
        <div className="min-h-0">
          {pending.length > 0 ? (
            <PendingApprovalsPanel pending={pending} hostnameByIp={hostnameByIp} />
          ) : (
            <RecentVerdictsPanel
              events={events}
              hostnameByIp={hostnameByIp}
              profileByIp={profileByIp}
            />
          )}
        </div>
      </div>
    </div>
  );
}

function RecentActivityPanel({
  events,
  hostnameByIp,
  profileByIp,
}: {
  events: EventRecord[];
  hostnameByIp: Map<string, string>;
  profileByIp: Map<string, string>;
}) {
  const rows = events.slice(0, 30);
  return (
    <Panel title="Recent activity" count={rows.length}>
      {rows.length === 0 ? (
        <Empty>No actions in the last 24h.</Empty>
      ) : (
        <ul className="divide-y divide-canvas-dark text-sm">
          {rows.map((e) => {
            const ip = e.agent_ip ?? "";
            return (
              <li key={(e.id ?? "") + e.ts} className="px-4 py-2">
                <div className="flex items-baseline justify-between gap-2">
                  <div className="truncate font-medium">{hostnameByIp.get(ip) || ip || "—"}</div>
                  <span className="shrink-0 text-[10px] text-text-muted">{fmtAge(e.ts)}</span>
                </div>
                <div className="text-xs text-text-muted truncate">
                  {profileByIp.get(ip) || <span className="italic">no profile</span>}
                  {" · "}
                  <VerdictTag action={e.action} /> <span className="font-mono">{e.method}</span>{" "}
                  {e.endpoint || e.host}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

function ConnectedDevicesPanel({ agents }: { agents: Agent[] }) {
  const sorted = useMemo(
    () => [...agents].sort((a, b) => new Date(b.last_at).getTime() - new Date(a.last_at).getTime()),
    [agents],
  );
  return (
    <Panel title="Connected devices" count={sorted.length}>
      {sorted.length === 0 ? (
        <Empty>No devices have checked in yet.</Empty>
      ) : (
        <ul className="divide-y divide-canvas-dark text-sm">
          {sorted.map((a) => (
            <li key={a.ip} className="px-4 py-2">
              <div className="flex items-baseline justify-between gap-2">
                <div className="truncate font-medium">{a.hostname || a.ip}</div>
                <span className="shrink-0 text-[10px] text-text-muted">{fmtAge(a.last_at)}</span>
              </div>
              <div className="text-xs text-text-muted truncate">
                {a.profile || <span className="italic">no profile</span>}
                {" · "}
                <span className="font-mono">{a.ip}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function UnconfiguredCredentialsPanel({
  unconfigured,
  total,
}: {
  unconfigured: Integration[];
  total: number;
}) {
  if (total === 0) {
    return (
      <Panel title="Credentials">
        <Empty>No credentials declared in gateway.hcl.</Empty>
      </Panel>
    );
  }
  if (unconfigured.length === 0) {
    return (
      <Panel title="Credentials" count={total}>
        <div className="px-4 py-6 text-sm text-text-muted">
          Every declared credential is connected. Nothing to action here.
        </div>
      </Panel>
    );
  }
  return (
    <Panel title="Unconfigured credentials" count={unconfigured.length}>
      <ul className="divide-y divide-canvas-dark text-sm">
        {unconfigured.map((i) => (
          <li key={i.id} className="px-4 py-3 flex items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="font-medium truncate">{i.name}</div>
              <div className="text-xs text-text-muted truncate">
                <span className="font-mono">{i.type}</span>
                {i.has_oauth && " · OAuth"}
                {i.has_tailscale_auth && " · Tailscale"}
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <span className="text-xs px-1.5 py-0.5 rounded-full bg-canvas-dark text-text-muted">
                needs setup
              </span>
              <a
                href="#/v2/settings"
                className="text-xs px-2 py-1 border border-rust-500 text-rust-700 hover:bg-rust-100 transition-colors"
              >
                Connect →
              </a>
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function PendingApprovalsPanel({
  pending,
  hostnameByIp,
}: {
  pending: HITLPending[];
  hostnameByIp: Map<string, string>;
}) {
  return (
    <Panel title="Pending approvals" count={pending.length} accent="awaiting verdict">
      <table className="w-full text-sm">
        <thead className="bg-canvas-muted text-left text-text-muted text-xs uppercase tracking-wider">
          <tr>
            <th className="px-4 py-2 font-medium">When</th>
            <th className="px-4 py-2 font-medium">Device</th>
            <th className="px-4 py-2 font-medium">Request</th>
            <th className="px-4 py-2 font-medium" />
          </tr>
        </thead>
        <tbody className="divide-y divide-canvas-dark">
          {pending.slice(0, 10).map((p) => (
            <tr key={p.id} className="bg-butter-100/40">
              <td className="px-4 py-2 font-mono text-xs whitespace-nowrap text-text-muted">
                {fmtDateTime(p.created_at)}
              </td>
              <td className="px-4 py-2 truncate max-w-[200px]">
                {p.agent_ip ? (hostnameByIp.get(p.agent_ip) ?? p.agent_ip) : "—"}
              </td>
              <td className="px-4 py-2 truncate max-w-[420px]">
                <span className="font-mono text-xs text-text-muted mr-1">{p.method}</span>
                {p.endpoint || p.host}
                {p.path && <span className="text-text-muted">{p.path}</span>}
              </td>
              <td className="px-4 py-2 text-right">
                <a
                  href="#/v2/actions"
                  className="text-xs px-2 py-0.5 bg-butter-500 text-text hover:bg-butter-600 transition-colors"
                >
                  Review →
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  );
}

function RecentVerdictsPanel({
  events,
  hostnameByIp,
  profileByIp,
}: {
  events: EventRecord[];
  hostnameByIp: Map<string, string>;
  profileByIp: Map<string, string>;
}) {
  const verdicts = events.filter((e) => e.action).slice(0, 10);
  return (
    <Panel title="Recent rule verdicts" count={verdicts.length}>
      {verdicts.length === 0 ? (
        <Empty>No rule verdicts recorded yet.</Empty>
      ) : (
        <table className="w-full text-sm">
          <thead className="bg-canvas-muted text-left text-text-muted text-xs uppercase tracking-wider">
            <tr>
              <th className="px-4 py-2 font-medium">When</th>
              <th className="px-4 py-2 font-medium">Device</th>
              <th className="px-4 py-2 font-medium">Profile</th>
              <th className="px-4 py-2 font-medium">Request</th>
              <th className="px-4 py-2 font-medium">Verdict</th>
              <th className="px-4 py-2 font-medium">Rule</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-canvas-dark">
            {verdicts.map((e) => {
              const ip = e.agent_ip ?? "";
              return (
                <tr key={(e.id ?? "") + e.ts}>
                  <td className="px-4 py-2 font-mono text-xs whitespace-nowrap text-text-muted">
                    {fmtDateTime(e.ts)}
                  </td>
                  <td className="px-4 py-2 truncate max-w-[160px]">
                    {hostnameByIp.get(ip) || ip || "—"}
                  </td>
                  <td className="px-4 py-2 text-text-muted">
                    {profileByIp.get(ip) || <span className="italic">—</span>}
                  </td>
                  <td className="px-4 py-2 truncate max-w-[360px]">
                    <span className="font-mono text-xs text-text-muted mr-1">{e.method}</span>
                    {e.endpoint || e.host}
                    {e.path && <span className="text-text-muted">{e.path}</span>}
                  </td>
                  <td className="px-4 py-2">
                    <VerdictTag action={e.action} />
                  </td>
                  <td className="px-4 py-2 text-text-muted">{e.rule || "—"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </Panel>
  );
}

// Panel is Overview's local sibling of Card — same chrome, but full
// height inside its grid cell and an internal scroll body so the
// 3fr / 1fr row split holds even when the underlying data overflows.
function Panel({
  title,
  count,
  accent,
  children,
}: {
  title: string;
  count?: number;
  accent?: string;
  children: ReactNode;
}) {
  return (
    <section className="flex flex-col h-full min-h-0 border border-canvas-dark bg-canvas-light">
      <header className="flex items-center justify-between border-b border-canvas-dark px-4 py-3 bg-canvas-muted shrink-0">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-text-muted">
          {title}
          {typeof count === "number" && count > 0 && (
            <span className="ml-2 inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-canvas-dark px-1.5 text-[10px] font-medium text-text">
              {count}
            </span>
          )}
          {accent && (
            <span className="ml-2 inline-flex h-4 items-center rounded-full bg-butter-100 px-1.5 text-[10px] font-medium text-butter-900">
              {accent}
            </span>
          )}
        </h2>
      </header>
      <div className="flex-1 min-h-0 overflow-auto">{children}</div>
    </section>
  );
}

function VerdictTag({ action }: { action?: string }) {
  if (!action) return <span className="text-text-muted text-xs">—</span>;
  const palette =
    action === "approved" || action === "allow"
      ? "bg-success-100 text-success-700"
      : action === "denied" || action === "deny"
        ? "bg-danger-100 text-danger-700"
        : "bg-canvas-dark text-text-muted";
  return <span className={`text-xs px-1.5 py-0.5 rounded-full ${palette}`}>{action}</span>;
}

function Empty({ children }: { children: ReactNode }) {
  return <div className="px-4 py-6 text-sm text-text-muted">{children}</div>;
}
