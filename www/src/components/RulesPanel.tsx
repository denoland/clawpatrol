import { useEffect, useState } from "react";
import { getDeviceRules, getRules, type RuleSummary } from "../lib/api";
import { RulesEditor } from "./RulesEditor";

// scope=undefined → global rules. scope=ip → per-device rules layered
// on top of global ones (shown together in the table; only device rules
// are editable here).
export function RulesPanel({ deviceIP, profile }: { deviceIP?: string; profile?: string }) {
  const [globalRules, setGlobalRules] = useState<RuleSummary[]>([]);
  const [deviceRules, setDeviceRules] = useState<RuleSummary[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);

  function reload() {
    getRules()
      .then((r) => setGlobalRules(r ?? []))
      .catch((e) => setErr(String(e)));
    if (deviceIP) {
      getDeviceRules(deviceIP)
        .then((r) => setDeviceRules(r ?? []))
        .catch(() => setDeviceRules([]));
    }
  }
  useEffect(() => {
    reload();
  }, [deviceIP]);
  // On a device page only show rules that apply to this device:
  // device-scoped rules + global rules whose profile is empty (catch-all)
  // or matches the device's assigned profile. Otherwise rules from
  // sibling profiles render as duplicate-looking rows.
  const inheritedFromGlobal = (globalRules ?? []).filter(
    (r) => !r.device && (!r.profile || !profile || r.profile === profile),
  );
  const rules = deviceIP
    ? [...(deviceRules ?? []), ...inheritedFromGlobal]
    : (globalRules ?? []);

  return (
    <div className="bg-white border border-[#e5e5e5] rounded overflow-hidden relative">
      <button
        onClick={() => setEditing(true)}
        className="absolute top-2 right-2 z-10 text-[10px] px-2 py-0.5 border border-[#e5e5e5] text-[#737373] rounded bg-white hover:border-[#a3a3a3] hover:text-[#171717]"
      >
        edit
      </button>
      {editing && (
        <RulesEditor
          deviceIP={deviceIP}
          onClose={() => setEditing(false)}
          onSaved={() => {
            reload();
          }}
        />
      )}
      {err && <div className="px-4 py-3 text-[11px] text-red-600">{err}</div>}
      <table className="w-full table-fixed border-collapse">
        <colgroup>
          <col style={{ width: 220 }} />
          <col style={{ width: 80 }} />
          <col />
          <col style={{ width: 110 }} />
        </colgroup>
        <thead>
          <tr className="border-b border-[#e5e5e5]">
            <Th>HOST</Th>
            <Th>ACTION</Th>
            <Th>MATCH</Th>
            <Th className="text-right">FLAGS</Th>
          </tr>
        </thead>
        <tbody>
          {rules.length === 0 && (
            <tr>
              <td colSpan={4} className="px-5 py-6 text-center text-[11px] text-[#a3a3a3]">
                no rules configured
              </td>
            </tr>
          )}
          {rules.map((r, i) => (
            <tr key={i} className="border-b border-[#f5f5f5] hover:bg-[#f9f9f9]">
              <Td>
                <div className="text-[12px] text-[#171717] truncate" title={r.host}>{r.host}</div>
                {r.auth && (
                  <div className="text-[10px] text-[#737373]">auth: {r.auth}</div>
                )}
              </Td>
              <Td>
                <ActionBadge action={(r.approve && r.approve.length > 0) ? "hitl" : (r.action || "allow")} />
              </Td>
              <Td>
                <MatchSummary r={r} />
              </Td>
              <Td className="text-right">
                <Flags r={r} />
              </Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ActionBadge({ action }: { action: string }) {
  const palette: Record<string, string> = {
    allow: "bg-[#f0fdf4] border-[#bbf7d0] text-[#166534]",
    deny: "bg-[#fef2f2] border-[#fecaca] text-[#991b1b]",
    hitl: "bg-[#fef3c7] border-[#fde68a] text-[#92400e]",
  };
  const cls = palette[action] || "bg-white border-[#e5e5e5] text-[#737373]";
  return (
    <span className={"text-[10px] uppercase tracking-[.08em] px-1.5 py-0.5 rounded border " + cls}>
      {action}
    </span>
  );
}

function MatchSummary({ r }: { r: RuleSummary }) {
  const m = r.match;
  const parts: string[] = [];
  if (m?.method?.length) parts.push(m.method.join("|"));
  if (m?.path) parts.push(m.path);
  if (m?.query) {
    for (const [k, v] of Object.entries(m.query)) {
      parts.push(`${k}=${v.join(",")}`);
    }
  }
  if (m?.headers) {
    for (const [k, v] of Object.entries(m.headers)) {
      parts.push(`${k}: ${v}`);
    }
  }
  if (r.reason) parts.push(`(${r.reason})`);
  if (!parts.length) return <span className="text-[10px] text-[#a3a3a3]">all</span>;
  return <span className="text-[11px] text-[#525252] truncate block" title={parts.join(" · ")}>{parts.join(" · ")}</span>;
}

function Flags({ r }: { r: RuleSummary }) {
  const flags = [];
  if (r.body) flags.push("body");
  if (r.ws_scan) flags.push("ws");
  if (r.port && r.port !== 443) flags.push(":" + r.port);
  if (!flags.length) return <span className="text-[10px] text-[#a3a3a3]">—</span>;
  return (
    <span className="inline-flex gap-1">
      {flags.map((f) => (
        <span key={f} className="text-[9px] uppercase tracking-[.08em] px-1 py-0.5 border border-[#e5e5e5] text-[#737373] rounded">
          {f}
        </span>
      ))}
    </span>
  );
}

function Th({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <th className={"px-3 sm:px-[14px] py-[9px] text-left text-[10px] uppercase tracking-[.09em] text-[#a3a3a3] font-medium bg-white " + className}>
      {children}
    </th>
  );
}

function Td({ children, className = "", ...rest }: { children: React.ReactNode; className?: string; title?: string }) {
  return (
    <td className={"px-3 sm:px-[14px] py-[9px] align-middle overflow-hidden " + className} {...rest}>
      {children}
    </td>
  );
}
