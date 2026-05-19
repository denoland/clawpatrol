import { useEffect, useMemo, useState } from "react";
import {
  type Agent,
  decideHITL,
  type EventRecord,
  getAction,
  getAnalytics,
  type HITLPending,
} from "../../lib/api";
import { fmtDateTime } from "../../lib/format";
import { Card } from "../cards/Card";
import { PageHeader } from "../cards/PageHeader";

// Actions — table of recent dispatched actions. clawpatrol stores
// these as an event log on the analytics endpoint (no dedicated
// `/api/actions` list call), so we tap `/api/analytics?range=24h`
// and project the EventRecord rows. `?action=<id>` opens an
// overlay detail.
//
// Approval-pending requests live on /api/hitl/pending — a different
// shape, but conceptually "actions waiting on a verdict." We weave
// them in as highlighted rows at the top of the table with inline
// approve/deny buttons; the old standalone Approvals page is gone.
export function V2ActionsPage({
  agents,
  pending,
  onRefresh,
  actionId,
}: {
  agents: Agent[];
  pending: HITLPending[];
  onRefresh: () => void;
  actionId?: string;
}) {
  const [rows, setRows] = useState<EventRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [agentFilter, setAgentFilter] = useState<string>("");
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    let cancel = false;
    async function load() {
      try {
        const r = await getAnalytics({ range: "24h", agent: agentFilter || undefined, limit: 200 });
        if (!cancel) setRows(r.events ?? []);
      } catch {
        /* swallow */
      } finally {
        if (!cancel) setLoading(false);
      }
    }
    load();
    const id = setInterval(load, 10_000);
    return () => {
      cancel = true;
      clearInterval(id);
    };
  }, [agentFilter]);

  const agentLabel = useMemo(() => {
    const m = new Map<string, string>();
    for (const a of agents) m.set(a.ip, a.hostname || a.ip);
    return m;
  }, [agents]);

  const visiblePending = useMemo(() => {
    if (!agentFilter) return pending;
    return pending.filter((p) => p.agent_ip === agentFilter);
  }, [pending, agentFilter]);

  async function decide(id: string, allow: boolean) {
    setBusy(id);
    try {
      await decideHITL(id, allow);
      onRefresh();
    } catch {
      /* swallow */
    } finally {
      setBusy(null);
    }
  }

  const pendCount = visiblePending.length;
  const totalRows = pendCount + rows.length;

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Actions"
        subhead="Recent dispatched actions. Rows awaiting your verdict glow at the top — approve or deny inline."
      >
        <select
          value={agentFilter}
          onChange={(e) => setAgentFilter(e.target.value)}
          className="border border-canvas-dark bg-canvas-light text-sm px-2 py-1"
        >
          <option value="">All agents</option>
          {agents.map((a) => (
            <option key={a.ip} value={a.ip}>
              {a.hostname || a.ip}
            </option>
          ))}
        </select>
      </PageHeader>

      <Card
        title={`Actions (24h)`}
        count={totalRows}
        countAccent={pendCount > 0 ? `${pendCount} awaiting` : undefined}
        tight
      >
        {loading ? (
          <div className="px-4 py-8 text-center text-sm text-text-muted">Loading…</div>
        ) : totalRows === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-text-muted">
            No actions in the last 24h.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-canvas-muted text-left text-text-muted text-xs uppercase tracking-wider">
              <tr>
                <th className="px-4 py-2 font-medium">When</th>
                <th className="px-4 py-2 font-medium">Agent</th>
                <th className="px-4 py-2 font-medium">Request</th>
                <th className="px-4 py-2 font-medium">Verdict</th>
                <th className="px-4 py-2 font-medium">Rule</th>
                <th className="px-4 py-2 font-medium">Approver</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-canvas-dark">
              {visiblePending.map((p) => {
                const isBusy = busy === p.id;
                return (
                  <tr
                    key={`pending-${p.id}`}
                    className="bg-butter-100/40 border-l-4 border-l-butter-500"
                  >
                    <td className="px-4 py-2 font-mono text-xs whitespace-nowrap text-text-muted">
                      {fmtDateTime(p.created_at)}
                    </td>
                    <td className="px-4 py-2 truncate max-w-[140px]">
                      {p.agent_ip ? (agentLabel.get(p.agent_ip) ?? p.agent_ip) : "—"}
                    </td>
                    <td className="px-4 py-2 truncate max-w-[320px]">
                      <span className="font-mono text-xs text-text-muted mr-1">{p.method}</span>
                      {p.endpoint || p.host}
                      {p.path && <span className="text-text-muted">{p.path}</span>}
                      {p.reason && (
                        <div className="text-[11px] text-text-muted italic mt-0.5">{p.reason}</div>
                      )}
                    </td>
                    <td className="px-4 py-2">
                      <span className="text-xs px-1.5 py-0.5 rounded-full bg-butter-100 text-butter-900 font-medium">
                        awaiting
                      </span>
                    </td>
                    <td className="px-4 py-2 text-text-muted">—</td>
                    <td className="px-4 py-2">
                      <div className="flex gap-1">
                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={() => decide(p.id, true)}
                          className="text-xs px-2 py-0.5 bg-success-500 text-canvas-light hover:bg-success-600 disabled:opacity-60"
                        >
                          Approve
                        </button>
                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={() => decide(p.id, false)}
                          className="text-xs px-2 py-0.5 border border-danger-500 text-danger-700 hover:bg-danger-100 disabled:opacity-60"
                        >
                          Deny
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
              {rows.slice(0, 200).map((e) => (
                <tr
                  key={(e.id ?? "") + e.ts}
                  className="hover:bg-canvas-muted cursor-pointer"
                  onClick={() => {
                    if (e.id) window.location.hash = `#/v2/actions/${encodeURIComponent(e.id)}`;
                  }}
                >
                  <td className="px-4 py-2 font-mono text-xs whitespace-nowrap text-text-muted">
                    {fmtDateTime(e.ts)}
                  </td>
                  <td className="px-4 py-2 truncate max-w-[140px]">
                    {e.agent_ip ? (agentLabel.get(e.agent_ip) ?? e.agent_ip) : "—"}
                  </td>
                  <td className="px-4 py-2 truncate max-w-[320px]">
                    <span className="font-mono text-xs text-text-muted mr-1">{e.method}</span>
                    {e.endpoint || e.host}
                    {e.path && <span className="text-text-muted">{e.path}</span>}
                  </td>
                  <td className="px-4 py-2">
                    <VerdictTag action={e.action} />
                  </td>
                  <td className="px-4 py-2 text-text-muted">{e.rule || "—"}</td>
                  <td className="px-4 py-2 text-text-muted">
                    {e.approver_type
                      ? `${e.approver_type}: ${e.approver_by ?? e.approver ?? "?"}`
                      : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {actionId && <ActionDetailModal id={actionId} />}
    </div>
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

function ActionDetailModal({ id }: { id: string }) {
  const [data, setData] = useState<EventRecord | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    getAction(id)
      .then(setData)
      .catch((e) => setErr(String(e?.message ?? e)));
  }, [id]);

  function close() {
    window.location.hash = "#/v2/actions";
  }

  return (
    <div
      className="fixed inset-0 bg-text/40 z-50 flex items-start justify-center p-6 overflow-auto"
      onClick={close}
    >
      <div
        className="bg-canvas-light border border-canvas-dark w-full max-w-3xl"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex items-center justify-between px-4 py-3 border-b border-canvas-dark bg-canvas-muted">
          <h2 className="text-sm font-semibold">Action {id}</h2>
          <button onClick={close} className="text-text-muted hover:text-text text-xl leading-none">
            ×
          </button>
        </header>
        <div className="p-4 text-sm">
          {err && <div className="text-danger-700">{err}</div>}
          {!err && !data && <div className="text-text-muted">Loading…</div>}
          {data && (
            <dl className="grid grid-cols-[140px_1fr] gap-y-2 gap-x-3 text-sm">
              <dt className="text-text-muted">When</dt>
              <dd className="font-mono text-xs">{fmtDateTime(data.ts)}</dd>
              <dt className="text-text-muted">Agent</dt>
              <dd className="font-mono text-xs">{data.agent_ip || "—"}</dd>
              <dt className="text-text-muted">Endpoint</dt>
              <dd>{data.endpoint || data.host}</dd>
              <dt className="text-text-muted">Method</dt>
              <dd className="font-mono text-xs">{data.method}</dd>
              <dt className="text-text-muted">Path</dt>
              <dd className="font-mono text-xs break-all">{data.path}</dd>
              <dt className="text-text-muted">Status</dt>
              <dd>{data.status ?? "—"}</dd>
              <dt className="text-text-muted">Verdict</dt>
              <dd>
                <VerdictTag action={data.action} />
              </dd>
              <dt className="text-text-muted">Rule</dt>
              <dd>{data.rule || "—"}</dd>
              <dt className="text-text-muted">Approver</dt>
              <dd>
                {data.approver_type
                  ? `${data.approver_type}: ${data.approver_by ?? data.approver ?? "?"}`
                  : "—"}
              </dd>
              {data.reason && (
                <>
                  <dt className="text-text-muted">Reason</dt>
                  <dd>{data.reason}</dd>
                </>
              )}
            </dl>
          )}
        </div>
      </div>
    </div>
  );
}
