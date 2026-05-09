import { useEffect, useState } from "react";
import { decideHITL, getHITLPending, type HITLPending } from "../lib/api";

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
    <div className="bg-white border border-[#e5e5e5] rounded overflow-hidden">
      <div className="px-4 py-2.5 text-[10px] uppercase tracking-[.12em] text-[#a3a3a3] border-b border-[#e5e5e5] flex items-center">
        <span>PENDING APPROVALS</span>
        <span className="ml-2 text-[#ea580c] tabular-nums">● {pending.length}</span>
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
                className="border-b border-[#f5f5f5] last:border-b-0 hover:bg-[#f9f9f9]"
              >
                <Td className="text-[11px] text-[#525252] tabular-nums truncate">{p.agent_ip}</Td>
                <Td className="text-[11px] uppercase font-semibold text-[#9a3412]">{p.method}</Td>
                <Td>
                  <span
                    className="text-[12px] text-[#171717] truncate block"
                    title={ep + sep + p.path}
                  >
                    <span className="text-[#737373]">
                      {ep}
                      {sep}
                    </span>
                    <span>{p.path}</span>
                  </span>
                  {p.reason && (
                    <div className="text-[10px] text-[#737373] truncate">{p.reason}</div>
                  )}
                </Td>
                <Td className="text-right">
                  <div className="flex gap-1.5 justify-end">
                    <button
                      onClick={() => decide(p.id, false)}
                      className="text-[11px] px-3 py-1 border border-[#fecaca] text-[#991b1b] rounded hover:bg-[#fef2f2]"
                    >
                      deny
                    </button>
                    <button
                      onClick={() => decide(p.id, true)}
                      className="text-[11px] px-3 py-1 bg-[#171717] text-white rounded hover:bg-[#000]"
                    >
                      allow
                    </button>
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
