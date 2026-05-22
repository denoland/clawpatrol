import { useEffect, useState } from "react";
import { decideHITL, getHITLPending, type HITLPending, type HITLResolveResult } from "../lib/api";
import { Button } from "./Button";

// HITL pending-approvals table. Polls /api/hitl/pending — list is
// short-lived (60s default), so SSE plumbing isn't worth it.
export function HITLBar() {
  const [pending, setPending] = useState<HITLPending[]>([]);
  const [notice, setNotice] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function tick() {
      try {
        const r = await getHITLPending();
        if (!cancelled) setPending(r ?? []);
      } catch {
        /* ignore transient */
      }
    }
    tick();
    const t = setInterval(tick, 1000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  async function decide(id: string, allow: boolean, confirmMsg: string) {
    if (!confirm(confirmMsg)) return;
    setNotice("");
    setPending((p) => p.filter((x) => x.id !== id));
    try {
      const result = await decideHITL(id, allow);
      if (!result.ok) setNotice(hitlDecisionNotice(result));
    } catch (e: any) {
      setNotice("HITL decision failed: " + (e?.message ?? e));
    }
  }

  if (pending.length === 0 && !notice) return null;

  return (
    <div className="bg-canvas border-1.5 border-navy overflow-hidden">
      <div className="px-4 py-2.5 text-xs font-mono uppercase tracking-wider text-navy font-bold flex items-center bg-navy-100 border-b border-navy">
        <span>Pending approvals</span>
        <span className="ml-2 text-rust-500 tabular-nums">● {pending.length}</span>
      </div>
      {notice && (
        <div className="px-4 py-2 text-xs text-rust-700 bg-canvas-muted border-t border-rust-200">
          {notice}
        </div>
      )}
      {pending.length > 0 && (
        <table className="w-full table-fixed border-collapse">
          <colgroup>
            <col style={{ width: 140 }} />
            <col style={{ width: 60 }} />
            <col />
            <col style={{ width: 160 }} />
          </colgroup>
          <tbody>
            {pending.map((p) => {
              const ep = p.endpoint || p.host;
              // HTTPS paths start with `/` and concatenate cleanly into
              // a URL ("api.anthropic.com/v1/messages"). SQL / k8s
              // paths don't start with `/`; insert a space so we get
              // "users-db UPDATE ..." rather than "users-dbUPDATE ...".
              const sep = p.path && !p.path.startsWith("/") ? " " : "";
              const approval = hitlApprovalDisplay(p);
              return (
                <tr
                  key={p.id}
                  className="border-b border-canvas-muted last:border-b-0 hover:bg-canvas-muted"
                >
                  <Td className="text-xs text-text-muted tabular-nums truncate">{p.agent_ip}</Td>
                  <Td className="font-mono text-xs uppercase font-semibold text-rust-700">
                    {p.method}
                  </Td>
                  <Td>
                    <span className="text-xs text-text truncate block" title={ep + sep + p.path}>
                      <span className="text-text-muted">
                        {ep}
                        {sep}
                      </span>
                      <span>{p.path}</span>
                    </span>
                    {p.reason && (
                      <div className="text-2xs text-text-muted truncate">{p.reason}</div>
                    )}
                    {approval && (
                      <div className="mt-1 flex gap-2 text-2xs leading-snug text-text-muted">
                        <span className="shrink-0 rounded-sm border border-navy-200 bg-navy-50 px-1.5 py-0.5 font-mono uppercase tracking-wide text-navy">
                          {approval.label}
                        </span>
                        <span className="whitespace-pre-line">{approval.message}</span>
                      </div>
                    )}
                  </Td>
                  <Td className="text-right">
                    <div className="flex gap-1.5 justify-end">
                      <Button
                        variant="outline"
                        onClick={() =>
                          decide(
                            p.id,
                            false,
                            `Deny this request?\n\n${p.method} ${ep}${sep}${p.path}`,
                          )
                        }
                      >
                        deny
                      </Button>
                      <Button
                        onClick={() => {
                          const verb = approval?.approveLabel ?? "allow";
                          const cap = verb.charAt(0).toUpperCase() + verb.slice(1);
                          decide(
                            p.id,
                            true,
                            `${cap} this request?\n\n${p.method} ${ep}${sep}${p.path}`,
                          );
                        }}
                      >
                        {approval?.approveLabel ?? "allow"}
                      </Button>
                    </div>
                  </Td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

function hitlApprovalDisplay(
  p: HITLPending,
): { label: string; message: string; approveLabel: string } | null {
  const effect = p.approval_effect;
  const state = p.operation_state;
  const message = (
    p.approval_message || hitlApprovalFallbackMessage(state, effect, p.upstream_called)
  ).trim();
  if (!message && !state && !effect) return null;
  if (effect === "create_retry_grant" || state === "pending_approval") {
    return {
      label: "retry grant",
      message:
        message || "Upstream has not been called. Approval allows one matching client retry.",
      approveLabel: "approve retry",
    };
  }
  if (p.upstream_called) {
    return {
      label: "upstream called",
      message: message || "The approved request has been retried and forwarded upstream.",
      approveLabel: "allow",
    };
  }
  return {
    label: state === "sync_waiting" ? "sync wait" : humanizeHITLState(state || "pending"),
    message: message || "Approval sends this request upstream immediately while the client waits.",
    approveLabel: "allow",
  };
}

function hitlApprovalFallbackMessage(
  state: HITLPending["operation_state"],
  effect: HITLPending["approval_effect"],
  upstreamCalled?: boolean,
): string {
  if (upstreamCalled) return "The approved request has been retried and forwarded upstream.";
  if (effect === "create_retry_grant" || state === "pending_approval") {
    return "Upstream has not been called. Approve will not send the request upstream now; it only allows one matching client retry.";
  }
  if (state === "approved_waiting_for_retry") {
    return "Approved. Waiting for the client to retry the original request. Upstream has not been called yet.";
  }
  if (state === "denied" || state === "expired" || state === "client_disconnected") {
    return "Upstream was not called.";
  }
  if (state === "sync_waiting" || effect === "execute_upstream") {
    return "Approval sends this request upstream immediately while the client waits.";
  }
  return "";
}

function humanizeHITLState(state: string): string {
  return state.replaceAll("_", " ");
}

function hitlDecisionNotice(result: HITLResolveResult): string {
  const detail = result.reason || result.state || "unknown";
  return `HITL request is no longer active: ${detail}`;
}

function Td({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <td className={"px-3 sm:px-3.5 py-2.5 align-middle overflow-hidden " + className}>
      {children}
    </td>
  );
}
