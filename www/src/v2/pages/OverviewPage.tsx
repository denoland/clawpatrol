import type { Agent, HITLPending, Integration } from "../../lib/api";
import { fmtBytes, fmtAge } from "../../lib/format";
import { Card } from "../cards/Card";
import { PageHeader } from "../cards/PageHeader";

// Overview — single-page summary of agents, integrations, pending
// approvals, and recent traffic. unclaw's Home splits by profile
// count (single-profile vs multi-profile mode); clawpatrol has no
// named-profile concept on the wire, so we render the single
// flat view all the time.
export function OverviewPage({
  agents,
  integrations,
  pending,
}: {
  agents: Agent[];
  integrations: Integration[];
  pending: HITLPending[];
}) {
  const totalReqs = agents.reduce((s, a) => s + a.reqs, 0);
  const totalBytes = agents.reduce((s, a) => s + a.bytes_in + a.bytes_out, 0);
  const connected = integrations.filter((i) => i.connected).length;
  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader title="Overview" subhead="Agents, integrations, and live activity at a glance." />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <Stat
          label="Devices"
          value={String(agents.length)}
          sub={`${pending.length} pending approval`}
        />
        <Stat label="Integrations" value={`${connected}/${integrations.length}`} sub="connected" />
        <Stat label="Total requests" value={fmtCount(totalReqs)} sub="all-time" />
        <Stat label="Total bytes" value={fmtBytes(totalBytes)} sub="all-time" />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-1">
          <Card title="Integrations" count={integrations.length}>
            {integrations.length === 0 ? (
              <EmptyMsg>None declared in gateway.hcl.</EmptyMsg>
            ) : (
              <ul className="text-sm divide-y divide-canvas-dark -mx-4">
                {integrations.slice(0, 12).map((i) => (
                  <li key={i.id} className="px-4 py-2 flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium truncate">{i.name}</div>
                      <div className="text-xs text-text-muted truncate">{i.type}</div>
                    </div>
                    <span
                      className={`text-xs px-1.5 py-0.5 rounded-full ${
                        i.connected
                          ? "bg-success-100 text-success-700"
                          : "bg-canvas-dark text-text-muted"
                      }`}
                    >
                      {i.connected ? "connected" : "—"}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
        <div className="lg:col-span-2">
          <Card title="Devices" count={agents.length}>
            {agents.length === 0 ? (
              <EmptyMsg>No agents have checked in yet.</EmptyMsg>
            ) : (
              <table className="w-full text-sm">
                <thead className="text-left text-text-muted text-xs uppercase tracking-wider">
                  <tr>
                    <th className="pb-2 font-medium">Hostname</th>
                    <th className="pb-2 font-medium">IP</th>
                    <th className="pb-2 font-medium text-right">Reqs</th>
                    <th className="pb-2 font-medium text-right">Last seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-canvas-dark">
                  {agents.slice(0, 10).map((a) => (
                    <tr key={a.ip}>
                      <td className="py-2 truncate max-w-[200px]">{a.hostname || "—"}</td>
                      <td className="py-2 font-mono text-xs">{a.ip}</td>
                      <td className="py-2 text-right">{fmtCount(a.reqs)}</td>
                      <td className="py-2 text-right text-text-muted">{fmtAge(a.last_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>

          {pending.length > 0 && (
            <Card title="Pending approvals" count={pending.length}>
              <ul className="text-sm divide-y divide-canvas-dark -mx-4">
                {pending.slice(0, 6).map((p) => (
                  <li key={p.id} className="px-4 py-2">
                    <div className="font-mono text-xs text-text-muted">{p.agent_ip}</div>
                    <div className="truncate">
                      {p.method} {p.endpoint || p.host}
                      {p.path && <span className="text-text-muted">{p.path}</span>}
                    </div>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, sub }: { label: string; value: string; sub: string }) {
  return (
    <div className="border border-canvas-dark bg-canvas-light px-4 py-3">
      <div className="text-xs uppercase tracking-wider text-text-muted">{label}</div>
      <div className="text-2xl font-semibold text-text mt-1">{value}</div>
      <div className="text-xs text-text-muted mt-0.5">{sub}</div>
    </div>
  );
}

function EmptyMsg({ children }: { children: string }) {
  return <div className="text-sm text-text-muted py-2">{children}</div>;
}

function fmtCount(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return (n / 1000).toFixed(n < 10_000 ? 1 : 0) + "k";
  return (n / 1_000_000).toFixed(1) + "M";
}
