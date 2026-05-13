import { useEffect, useState } from "react";
import { decideHITL, getHITLPending, type HITLPending } from "../lib/api";
import { Button } from "./Button";

// HITL pending-approvals table. Polls /api/hitl/pending — list is
// short-lived (60s default), so SSE plumbing isn't worth it.
export function HITLBar() {
  const [pending, setPending] = useState<HITLPending[]>([]);

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

  async function decide(id: string, allow: boolean) {
    setPending((p) => p.filter((x) => x.id !== id));
    try {
      await decideHITL(id, allow);
    } catch {
      /* swallow — request likely already timed out */
    }
  }

  if (pending.length === 0) return null;

  return (
    <div className="bg-canvas-light border-2 border-navy overflow-hidden">
      <div className="px-4 py-2.5 text-2xs uppercase tracking-[.12em] text-navy font-bold flex items-center bg-navy-100">
        <span>PENDING APPROVALS</span>
        <span className="ml-2 text-rust-500 tabular-nums">● {pending.length}</span>
      </div>
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
            return (
              <tr
                key={p.id}
                className="border-b border-canvas-muted last:border-b-0 hover:bg-navy-50"
              >
                <Td className="text-xs text-text-muted tabular-nums truncate">{p.agent_ip}</Td>
                <Td className="text-xs uppercase font-semibold text-rust-700">{p.method}</Td>
                <Td>
                  <span className="text-xs text-text truncate block" title={ep + sep + p.path}>
                    <span className="text-text-muted">
                      {ep}
                      {sep}
                    </span>
                    <span>{p.path}</span>
                  </span>
                  {p.reason && <div className="text-2xs text-text-muted truncate">{p.reason}</div>}
                </Td>
                <Td className="text-right">
                  <div className="flex gap-1.5 justify-end">
                    <Button variant="outline" onClick={() => decide(p.id, false)}>
                      deny
                    </Button>
                    <Button onClick={() => decide(p.id, true)}>allow</Button>
                  </div>
                </Td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function Td({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <td className={"px-3 sm:px-[14px] py-[9px] align-middle overflow-hidden " + className}>
      {children}
    </td>
  );
}
