import { useEffect, useState } from "react";
import { decideHITL, getHITLPending, type HITLPending, type HITLResolveResult } from "../lib/api";
import { Button } from "./Button";

export function HITLBar({ agentIP }: { agentIP?: string } = {}) {
  const [pending, setPending] = useState<HITLPending[]>([]);
  const [justResolved, setJustResolved] = useState<HITLPending[]>([]);
  const [notice, setNotice] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function tick() {
      try {
        const r = await getHITLPending();
        if (!cancelled) {
          const all = r ?? [];
          const incoming = agentIP ? all.filter((x) => x.agent_ip === agentIP) : all;
          // Detect >0 → 0 transition: briefly flash green "Approved" cards.
          setPending((prev) => {
            if (prev.length > 0 && incoming.length === 0) {
              setJustResolved(prev);
              setTimeout(() => setJustResolved([]), 2500);
            }
            return incoming;
          });
        }
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
  }, [agentIP]);

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

  if (pending.length === 0 && justResolved.length === 0 && !notice) return null;

  return (
    <div className="space-y-1.5">
      {notice && (
        <div className="px-4 py-2 text-xs text-rust-700 bg-canvas border-1.5 border-rust-200">
          {notice}
        </div>
      )}
      {justResolved.map((r) => (
        <ResolvedCard key={r.id} item={r} />
      ))}
      {pending.map((p) => (
        <PendingCard key={p.id} item={p} onDecide={decide} />
      ))}
    </div>
  );
}

function PendingCard({
  item,
  onDecide,
}: {
  item: HITLPending;
  onDecide: (id: string, allow: boolean, msg: string) => void;
}) {
  const ep = item.endpoint || item.host;
  const sep = item.path && !item.path.startsWith("/") ? " " : "";
  const target = `${item.method} ${ep}${sep}${item.path}`;
  const approveLabel =
    item.approval_effect === "create_retry_grant" || item.operation_state === "pending_approval"
      ? "approve retry"
      : "allow";

  return (
    <div className="border-l-4 border-butter-400 bg-canvas border-y border-r border-navy overflow-hidden">
      <div className="px-4 py-3 flex items-center gap-3 min-w-0">
        {/* status badge */}
        <div className="flex items-center gap-1.5 shrink-0">
          <span className="w-2 h-2 rounded-full bg-butter-400 animate-pulse" />
          <span className="font-mono text-2xs font-bold uppercase tracking-wider text-butter-700 whitespace-nowrap">
            awaiting approval
          </span>
        </div>
        {/* request */}
        <span className="font-mono text-xs font-semibold text-text-muted shrink-0">
          {item.method}
        </span>
        <span className="font-mono text-xs text-text truncate flex-1 min-w-0" title={target}>
          {ep}
          {sep}
          {item.path}
        </span>
        {/* actions */}
        <div className="flex gap-1.5 shrink-0">
          <Button
            variant="outline"
            onClick={() => onDecide(item.id, false, `Deny this request?\n\n${target}`)}
          >
            deny
          </Button>
          <Button
            onClick={() => {
              const cap = approveLabel.charAt(0).toUpperCase() + approveLabel.slice(1);
              onDecide(item.id, true, `${cap}?\n\n${target}`);
            }}
          >
            {approveLabel}
          </Button>
        </div>
      </div>
      {(item.body_sample || item.ua || item.reason) && (
        <div className="px-4 pb-2.5 pt-1.5 border-t border-canvas-muted space-y-0.5">
          {item.body_sample && (
            <div className="font-mono text-2xs text-text truncate">{item.body_sample}</div>
          )}
          <div className="text-2xs text-text-muted truncate">
            {item.ua && (
              <span>
                requested by <span className="font-mono text-text">{item.ua}</span>
              </span>
            )}
            {item.ua && item.reason && <span className="mx-1.5">·</span>}
            {item.reason && <span>{item.reason}</span>}
          </div>
        </div>
      )}
    </div>
  );
}

function ResolvedCard({ item }: { item: HITLPending }) {
  const ep = item.endpoint || item.host;
  const sep = item.path && !item.path.startsWith("/") ? " " : "";
  return (
    <div className="border-l-4 border-success-500 bg-canvas border-y border-r border-navy px-4 py-3 flex items-center gap-3 min-w-0">
      <div className="flex items-center gap-1.5 shrink-0">
        <span className="w-2 h-2 rounded-full bg-success-500" />
        <span className="font-mono text-2xs font-bold uppercase tracking-wider text-success-700 whitespace-nowrap">
          approved
        </span>
      </div>
      <span className="font-mono text-xs font-semibold text-text-muted shrink-0">
        {item.method}
      </span>
      <span className="font-mono text-xs text-text truncate flex-1 min-w-0">
        {ep}
        {sep}
        {item.path}
      </span>
    </div>
  );
}

function hitlDecisionNotice(result: HITLResolveResult): string {
  const detail = result.reason || result.state || "unknown";
  return `HITL request is no longer active: ${detail}`;
}
