import { useEffect, useMemo, useState } from "react";
import { getDeviceRules, getRules, type RuleSummary } from "../lib/api";
import { EditGlyph } from "./Logos";
import { RulesEditor } from "./RulesEditor";

// Rules panel. On a device page (deviceIP set) it splits rules into
// two sections — profile rules (read-only here, edited via gateway.hcl)
// and device rules (editable in-place via the device's HCL block).
// Each section has its own pencil button on the right of the header.
//
// On the global view (no deviceIP) there's one section showing every
// profile's rules with a single pencil opening the whole gateway.hcl.
export function RulesPanel({ deviceIP }: { deviceIP?: string; profile?: string }) {
  const [rows, setRows] = useState<RuleSummary[]>([]);
  const [err, setErr] = useState<string | null>(null);
  // Which editor is open. "" = none, "global" = gateway.hcl,
  // "device" = device block.
  const [editing, setEditing] = useState<"" | "global" | "device">("");

  function reload() {
    const fetcher = deviceIP ? getDeviceRules(deviceIP) : getRules();
    fetcher
      .then((r) => setRows(r ?? []))
      .catch((e) => setErr(String(e)));
  }
  useEffect(() => {
    reload();
  }, [deviceIP]);

  const profileRows = useMemo(
    () => rows.filter((r) => !r.device_ip),
    [rows],
  );
  const deviceRows = useMemo(
    () => rows.filter((r) => r.device_ip === deviceIP),
    [rows, deviceIP],
  );

  return (
    <div className="bg-white border border-[#e5e5e5] rounded">
      {err && <div className="px-4 py-3 text-[11px] text-red-600">{err}</div>}

      <Section
        title={deviceIP ? "Profile rules" : "Rules (all profiles)"}
        count={profileRows.length}
        onEdit={() => setEditing("global")}
        editLabel="edit gateway.hcl"
        rows={profileRows}
      />

      {deviceIP && (
        <Section
          title={`Device rules · ${deviceIP}`}
          count={deviceRows.length}
          onEdit={() => setEditing("device")}
          editLabel="edit device block"
          rows={deviceRows}
          emptyHint="no per-device overrides — click the pencil to add one"
        />
      )}

      {editing && (
        <RulesEditor
          deviceIP={editing === "device" ? deviceIP : undefined}
          onClose={() => setEditing("")}
          onSaved={() => {
            reload();
            setEditing("");
          }}
        />
      )}
    </div>
  );
}

function Section({
  title,
  count,
  rows,
  onEdit,
  editLabel,
  emptyHint,
}: {
  title: string;
  count: number;
  rows: RuleSummary[];
  onEdit: () => void;
  editLabel: string;
  emptyHint?: string;
}) {
  const groups = useMemo(() => {
    const m = new Map<string, { endpoint: string; family: string; rules: RuleSummary[] }>();
    for (const r of rows) {
      const g = m.get(r.endpoint) ?? { endpoint: r.endpoint, family: r.family, rules: [] };
      g.rules.push(r);
      m.set(r.endpoint, g);
    }
    return Array.from(m.values()).sort((a, b) => a.endpoint.localeCompare(b.endpoint));
  }, [rows]);

  return (
    <div className="border-b border-[#e5e5e5] last:border-b-0">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-[#e5e5e5]">
        <div className="text-[11px] uppercase tracking-[.09em] text-[#a3a3a3] font-medium">
          {title}
        </div>
        <span className="text-[10px] text-[#a3a3a3] tabular-nums">
          {count} rule{count === 1 ? "" : "s"}
        </span>
        <button
          onClick={onEdit}
          title={editLabel}
          className="ml-auto p-1 text-[#a3a3a3] hover:text-[#171717] transition-colors"
        >
          <EditGlyph />
        </button>
      </div>
      {groups.length === 0 ? (
        <div className="px-5 py-5 text-center text-[11px] text-[#a3a3a3]">
          {emptyHint ?? "no rules configured"}
        </div>
      ) : (
        <div className="flex flex-col">
          {groups.map((g) => (
            <EndpointGroup key={g.endpoint} group={g} />
          ))}
        </div>
      )}
    </div>
  );
}

function EndpointGroup({
  group,
}: {
  group: { endpoint: string; family: string; rules: RuleSummary[] };
}) {
  return (
    <div className="border-b border-[#f5f5f5] last:border-b-0">
      <div className="flex items-center gap-2 px-4 py-2 bg-[#fafafa]">
        <FamilyDot family={group.family} />
        <span className="text-[12px] font-mono text-[#171717]">{group.endpoint}</span>
        <span className="text-[10px] text-[#a3a3a3]">{group.family}</span>
        <span className="ml-auto text-[10px] text-[#737373] tabular-nums">
          {group.rules.length} rule{group.rules.length === 1 ? "" : "s"}
        </span>
      </div>
      {group.rules.map((r, i) => (
        <RuleRow key={`${r.name}/${i}`} rule={r} />
      ))}
    </div>
  );
}

function RuleRow({ rule: r }: { rule: RuleSummary }) {
  return (
    <div
      className={
        "flex items-start gap-3 px-4 py-2 border-t border-[#f5f5f5] hover:bg-[#fcfcfc] " +
        (r.disabled ? "opacity-50" : "")
      }
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <Verdict r={r} />
          {r.reason && (
            <span className="text-[12px] text-[#525252] truncate" title={r.reason}>
              {r.reason}
            </span>
          )}
        </div>
        <div className="text-[11px] text-[#737373] mt-1 font-mono truncate" title={renderMatch(r.match)}>
          {renderMatch(r.match)}
        </div>
      </div>
      <div className="flex flex-col items-end gap-0.5 flex-shrink-0">
        <span className="text-[11px] text-[#a3a3a3] truncate max-w-[160px]" title={r.name}>
          {r.name}
        </span>
        {r.priority ? (
          <span className="text-[10px] text-[#a3a3a3] tabular-nums">
            p{r.priority > 0 ? "+" : ""}{r.priority}
          </span>
        ) : null}
      </div>
    </div>
  );
}

function FamilyDot({ family }: { family: string }) {
  const palette: Record<string, string> = {
    https: "bg-[#3b82f6]",
    sql: "bg-[#f59e0b]",
    k8s: "bg-[#8b5cf6]",
  };
  return (
    <span
      className={"inline-block w-[6px] h-[6px] rounded-full " + (palette[family] ?? "bg-[#a3a3a3]")}
      title={family}
    />
  );
}

// Verdict is the badge on the left of a rule row — bare verb (DENY /
// ALLOW / APPROVE) without inlined reason; reason text renders next
// to it in the row layout, kept separate so long reasons don't
// stretch the badge.
function Verdict({ r }: { r: RuleSummary }) {
  if (r.approve && r.approve.length > 0) {
    const names = r.approve.map((s) => s.name).join(" → ");
    return (
      <span
        className="text-[10px] uppercase tracking-[.08em] px-1.5 py-0.5 rounded border bg-[#fef9c3] border-[#fde68a] text-[#854d0e]"
        title={names}
      >
        approve
      </span>
    );
  }
  const verdict = r.verdict || "allow";
  const palette: Record<string, string> = {
    allow: "bg-[#f0fdf4] border-[#bbf7d0] text-[#166534]",
    deny: "bg-[#fef2f2] border-[#fecaca] text-[#991b1b]",
  };
  const cls = palette[verdict] ?? "bg-white border-[#e5e5e5] text-[#737373]";
  return (
    <span
      className={"text-[10px] uppercase tracking-[.08em] px-1.5 py-0.5 rounded border " + cls}
    >
      {verdict}
    </span>
  );
}

// renderMatch flattens the match map into a readable line. Each
// entry: scalar → `key = value`; single-element list → `key = value`;
// multi-element list → `key in [a, b, c]`. Multiple match keys join
// with " · ".
function renderMatch(match?: Record<string, unknown>): string {
  if (!match || Object.keys(match).length === 0) return "matches every request";
  const parts: string[] = [];
  for (const [k, v] of Object.entries(match)) {
    if (Array.isArray(v)) {
      if (v.length === 1) parts.push(`${k} = ${scalar(v[0])}`);
      else parts.push(`${k} in [${v.map(scalar).join(", ")}]`);
    } else {
      parts.push(`${k} = ${scalar(v)}`);
    }
  }
  return parts.join(" · ");
}

function scalar(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}
