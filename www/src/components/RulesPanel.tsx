import { useEffect, useState } from "react";
import { getDeviceRules, getRules, type RuleSummary } from "../lib/api";
import { RulesEditor } from "./RulesEditor";

// Rule view, read-only on the new policy. deviceIP=undefined → all
// rules across every profile, deviceIP=ip → rules in the device's
// profile only. Edits flow through the gateway HCL editor (the
// "edit" button opens it) — the v14 schema's first-match-wins
// priority + approve-chain shape doesn't fit the legacy per-row
// edit UX cleanly.
export function RulesPanel({ deviceIP }: { deviceIP?: string; profile?: string }) {
  const [rows, setRows] = useState<RuleSummary[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);

  function reload() {
    const fetcher = deviceIP ? getDeviceRules(deviceIP) : getRules();
    fetcher
      .then((r) => setRows(r ?? []))
      .catch((e) => setErr(String(e)));
  }
  useEffect(() => {
    reload();
  }, [deviceIP]);

  return (
    <div className="bg-white border border-[#e5e5e5] rounded overflow-hidden relative">
      <button
        onClick={() => setEditing(true)}
        className="absolute top-2 right-2 z-10 text-[10px] px-2 py-0.5 border border-[#e5e5e5] text-[#737373] rounded bg-white hover:border-[#a3a3a3] hover:text-[#171717]"
      >
        edit gateway.hcl
      </button>
      {editing && (
        <RulesEditor
          onClose={() => setEditing(false)}
          onSaved={() => reload()}
        />
      )}
      {err && <div className="px-4 py-3 text-[11px] text-red-600">{err}</div>}
      <table className="w-full table-fixed border-collapse">
        <colgroup>
          <col style={{ width: 200 }} />
          <col style={{ width: 64 }} />
          <col style={{ width: 140 }} />
          <col />
          <col style={{ width: 96 }} />
          <col style={{ width: 56 }} />
        </colgroup>
        <thead>
          <tr className="border-b border-[#e5e5e5]">
            <Th>RULE</Th>
            <Th>FAMILY</Th>
            <Th>ENDPOINT</Th>
            <Th>MATCH</Th>
            <Th>OUTCOME</Th>
            <Th className="text-right">PRIORITY</Th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td colSpan={6} className="px-5 py-6 text-center text-[11px] text-[#a3a3a3]">
                no rules configured
              </td>
            </tr>
          )}
          {rows.map((r, i) => (
            <tr
              key={`${r.profile ?? ""}/${r.endpoint}/${r.name}/${i}`}
              className={
                "border-b border-[#f5f5f5] hover:bg-[#f9f9f9] " +
                (r.disabled ? "opacity-50" : "")
              }
            >
              <Td>
                <div className="text-[12px] text-[#171717] truncate" title={r.name}>
                  {r.name}
                </div>
                {r.profile && (
                  <div className="text-[10px] text-[#737373]">profile: {r.profile}</div>
                )}
              </Td>
              <Td>
                <FamilyBadge family={r.family} />
              </Td>
              <Td>
                <span className="text-[11px] text-[#525252] truncate block" title={r.endpoint}>
                  {r.endpoint}
                </span>
              </Td>
              <Td>
                <MatchSummary match={r.match} />
              </Td>
              <Td>
                <Outcome r={r} />
              </Td>
              <Td className="text-right text-[11px] text-[#737373]">
                {priorityLabel(r.priority)}
              </Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function priorityLabel(p?: number): string {
  if (!p) return "0";
  return p > 0 ? `+${p}` : String(p);
}

function FamilyBadge({ family }: { family: string }) {
  const palette: Record<string, string> = {
    https: "bg-[#eff6ff] border-[#bfdbfe] text-[#1d4ed8]",
    sql: "bg-[#fef3c7] border-[#fde68a] text-[#92400e]",
    k8s: "bg-[#ede9fe] border-[#ddd6fe] text-[#5b21b6]",
  };
  const cls = palette[family] || "bg-white border-[#e5e5e5] text-[#737373]";
  return (
    <span className={"text-[10px] uppercase tracking-[.08em] px-1.5 py-0.5 rounded border " + cls}>
      {family}
    </span>
  );
}

function Outcome({ r }: { r: RuleSummary }) {
  if (r.approve && r.approve.length > 0) {
    const names = r.approve.map((s) => s.name).join(" → ");
    return (
      <span
        className="text-[10px] uppercase tracking-[.08em] px-1.5 py-0.5 rounded border bg-[#fef9c3] border-[#fde68a] text-[#854d0e]"
        title={names}
      >
        approve: {names}
      </span>
    );
  }
  const verdict = r.verdict || "allow";
  const palette: Record<string, string> = {
    allow: "bg-[#f0fdf4] border-[#bbf7d0] text-[#166534]",
    deny: "bg-[#fef2f2] border-[#fecaca] text-[#991b1b]",
    hitl: "bg-[#fef3c7] border-[#fde68a] text-[#92400e]",
  };
  const cls = palette[verdict] || "bg-white border-[#e5e5e5] text-[#737373]";
  return (
    <span className={"text-[10px] uppercase tracking-[.08em] px-1.5 py-0.5 rounded border " + cls}>
      {verdict}
      {r.reason ? ` · ${r.reason}` : ""}
    </span>
  );
}

// MatchSummary renders the family-agnostic match map as
// "key=value · key=[a,b]" parts, truncating to keep the row tidy.
// "credential = X" shows up here too, since v14 lets a rule pin the
// credential a request was dispatched against.
function MatchSummary({ match }: { match?: Record<string, unknown> }) {
  if (!match || Object.keys(match).length === 0) {
    return <span className="text-[10px] text-[#a3a3a3]">all</span>;
  }
  const parts: string[] = [];
  for (const [k, v] of Object.entries(match)) {
    parts.push(`${k}=${formatValue(v)}`);
  }
  const text = parts.join(" · ");
  return (
    <span className="text-[11px] text-[#525252] truncate block" title={text}>
      {text}
    </span>
  );
}

function formatValue(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map((x) => formatValue(x)).join(",")}]`;
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function Th({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <th
      className={
        "px-3 sm:px-[14px] py-[9px] text-left text-[10px] uppercase tracking-[.09em] text-[#a3a3a3] font-medium bg-white " +
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
    <td
      className={"px-3 sm:px-[14px] py-[9px] align-middle overflow-hidden " + className}
      {...rest}
    >
      {children}
    </td>
  );
}
