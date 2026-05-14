import { useState } from "react";
import { decideHITL, type HITLPending } from "../../lib/api";
import { fmtDateTime } from "../../lib/format";
import { Card } from "../cards/Card";
import { PageHeader } from "../cards/PageHeader";

// Approvals — unclaw calls this "Pending"; cl-r3e asks for the
// rename. clawpatrol's HITL endpoint returns the same pending-
// action shape we render here. cl-r3e classifies this as read-only
// for fields that today edit, but the HITL approve/deny IS the
// dashboard's only way to resolve a pending request, so we keep
// the two action buttons live. They map to the same
// /api/hitl/decide endpoint the v1 HITLBar uses.
export function ApprovalsPage({
  pending,
  onRefresh,
}: {
  pending: HITLPending[];
  onRefresh: () => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);

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

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Approvals"
        subhead="Requests waiting on a human verdict. Approving a request lets it
          through; denying short-circuits it with a 403."
      />

      <Card title="Pending" count={pending.length} tight>
        {pending.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-text-muted">
            Nothing waiting on you. The queue is empty.
          </div>
        ) : (
          <ul className="divide-y divide-canvas-dark">
            {pending.map((p) => {
              const isBusy = busy === p.id;
              return (
                <li key={p.id} className="px-4 py-3 flex items-start gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="text-xs text-text-muted font-mono">
                      {fmtDateTime(p.created_at)} · {p.agent_ip}
                    </div>
                    <div className="mt-1">
                      <span className="font-mono text-xs text-text-muted mr-1">{p.method}</span>
                      <span className="font-medium">{p.endpoint || p.host}</span>
                      {p.path && <span className="text-text-muted ml-1 break-all">{p.path}</span>}
                    </div>
                    {p.reason && (
                      <div className="mt-1 text-xs text-text-muted italic">{p.reason}</div>
                    )}
                    {p.body_sample && (
                      <pre className="mt-2 bg-canvas-muted border border-canvas-dark px-2 py-1 text-[11px] font-mono overflow-x-auto max-h-32">
                        {p.body_sample}
                      </pre>
                    )}
                  </div>
                  <div className="flex flex-col gap-1 shrink-0">
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => decide(p.id, true)}
                      className="text-xs px-3 py-1 bg-success-500 text-canvas-light hover:bg-success-600 disabled:opacity-60"
                    >
                      Approve
                    </button>
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => decide(p.id, false)}
                      className="text-xs px-3 py-1 border border-danger-500 text-danger-700 hover:bg-danger-100 disabled:opacity-60"
                    >
                      Deny
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Card>
    </div>
  );
}
