// slop.dev-style table for agent sessions running on a device.

import type { Session } from "../lib/api";
import { fmtAge, fmtTokens, shortModel } from "../lib/format";
import { useRef, useState } from "react";
import { Sparkline } from "./Sparkline";
import { AgentTypeIcon } from "./AgentTypeIcon";
import { CtxDonut } from "./CtxDonut";

export function SessionsTable({ sessions: all }: { sessions: Session[] }) {
  const sessions = (all ?? []).filter((s) => s.title && s.title.length > 0);
  return (
    <div className="bg-canvas border-1.5 border-navy overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full table-fixed border-collapse" style={{ minWidth: 800 }}>
          <colgroup>
            <col />
            <col style={{ width: 110 }} />
            <col style={{ width: 60 }} />
            <col style={{ width: 60 }} />
            <col style={{ width: 200 }} />
          </colgroup>
          <thead className="bg-navy-100 border-b border-navy">
            <tr>
              <Th>Session</Th>
              <Th>Activity</Th>
              <Th className="text-right">Age</Th>
              <Th className="text-right">Reqs</Th>
              <Th>Model/Ctx</Th>
            </tr>
          </thead>
          <tbody>
            {sessions.length === 0 && (
              <tr>
                <td colSpan={5} className="px-5 py-8 text-center text-xs text-text-subtle">
                  It's empty in here
                </td>
              </tr>
            )}
            {sessions.map((s, i) => (
              <tr key={i} className="border-b border-canvas-muted hover:bg-canvas-muted">
                <Td>
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="w-[5px] h-[5px] rounded-full bg-success-500 shrink-0" />
                    <AgentTypeIcon type={s.type} className="w-[14px] h-[14px] shrink-0" />
                    <div className="min-w-0">
                      <div className="text-xs text-text truncate" title={s.title}>
                        {s.title}
                      </div>
                      {s.id && (
                        <div className="text-2xs text-text-subtle tabular-nums truncate">
                          {s.id}
                        </div>
                      )}
                    </div>
                  </div>
                </Td>
                <Td>
                  <Sparkline data={s.activity} width={100} height={16} />
                </Td>
                <Td className="text-xs text-text-muted tabular-nums text-right">
                  {fmtAge(s.first_at)}
                </Td>
                <Td className="text-xs text-text-muted tabular-nums text-right">{s.reqs}</Td>
                <Td>
                  {s.model ? (
                    <div className="flex items-center gap-1.5 min-w-0">
                      <span className="text-xs text-text-muted truncate" title={s.model}>
                        {shortModel(s.model)}
                      </span>
                      <ModelDonut session={s} />
                    </div>
                  ) : (
                    <span className="text-2xs text-text-subtle">—</span>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ModelDonut({ session: s }: { session: Session }) {
  const ref = useRef<HTMLDivElement>(null);
  const [tip, setTip] = useState<{ top: number; left: number } | null>(null);
  const pct = s.ctx_used && s.ctx_max ? (s.ctx_used / s.ctx_max) * 100 : 0;
  // position:fixed so the tooltip escapes the table's overflow:hidden
  // clip — anchor it to the donut's bounding rect computed on hover.
  function onEnter() {
    const r = ref.current?.getBoundingClientRect();
    if (!r) return;
    setTip({ top: r.bottom + 6, left: r.left + r.width / 2 });
  }
  return (
    <div
      ref={ref}
      className="relative inline-flex"
      onMouseEnter={onEnter}
      onMouseLeave={() => setTip(null)}
    >
      <CtxDonut used={s.ctx_used} max={s.ctx_max} size={18} />
      {tip && s.ctx_used && (
        <div
          className="fixed z-50 -translate-x-1/2 px-2 py-1 bg-navy text-canvas text-2xs rounded shadow whitespace-nowrap tabular-nums pointer-events-none"
          style={{ top: tip.top, left: tip.left }}
        >
          {fmtTokens(s.tokens_in)} in · {fmtTokens(s.tokens_out)} out
          {s.ctx_max
            ? ` · ${fmtTokens(s.ctx_used)}/${fmtTokens(s.ctx_max)} (${pct.toFixed(0)}%)`
            : ""}
        </div>
      )}
    </div>
  );
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
