import { useEffect, useMemo, useState } from "react";
import { getRules, type RuleSummary } from "../lib/api";
import { Tag, type Tone } from "./Tag";

// Rules panel. Profile-level rules only — device-specific overrides
// are gone. Display-only — operators edit gateway.hcl out-of-band and
// push via SSH. Device pages pass `profile` so the listing filters to
// the device's profile.
export function RulesPanel({ profile }: { deviceIP?: string; profile?: string }) {
  const [rows, setRows] = useState<RuleSummary[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getRules()
      .then((r) => setRows(r ?? []))
      .catch((e) => setErr(String(e)));
  }, []);

  const visible = useMemo(
    () => (profile ? rows.filter((r) => !r.profile || r.profile === profile) : rows),
    [rows, profile],
  );

  return (
    <div className="bg-canvas border-1.5 border-navy">
      {err && <div className="px-4 py-3 text-xs text-rust-700">{err}</div>}
      <Section title="Rules" rows={visible} />
    </div>
  );
}

function Section({
  title,
  rows,
  emptyHint,
}: {
  title: string;
  rows: RuleSummary[];
  emptyHint?: string;
}) {
  // Group by endpoint. Server already sorts rules within an endpoint
  // by priority desc. Endpoint groups themselves sort alphabetically.
  const groups = useMemo(() => {
    const m = new Map<string, { endpoint: string; family: string; rules: RuleSummary[] }>();
    for (const r of rows) {
      const g = m.get(r.endpoint) ?? {
        endpoint: r.endpoint,
        family: r.family,
        rules: [],
      };
      g.rules.push(r);
      m.set(r.endpoint, g);
    }
    return Array.from(m.values()).sort((a, b) => a.endpoint.localeCompare(b.endpoint));
  }, [rows]);

  return (
    <div className="last:border-b-0">
      <div className="flex items-center px-4 py-2.5 bg-navy-100 border-b border-navy">
        <div className="font-mono text-xs uppercase tracking-wider text-navy font-bold">
          {title}
        </div>
        <span className="ml-2 text-2xs text-navy/70 tabular-nums">
          {rows.length} rule{rows.length === 1 ? "" : "s"}
        </span>
      </div>
      {groups.length === 0 ? (
        <div className="px-5 py-5 text-center text-xs text-text-subtle">
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
    <div className="border-b border-canvas-muted last:border-b-0">
      <div className="flex items-center gap-2 px-4 py-2 bg-navy-50">
        <FamilyDot family={group.family} />
        <span className="text-xs font-mono text-text">{group.endpoint}</span>
        <span className="text-2xs text-navy/70">{group.family}</span>
        <span className="ml-auto text-2xs text-navy/70 tabular-nums">
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
        "flex items-start gap-3 px-4 py-2 border-t border-canvas-muted hover:bg-canvas-muted " +
        (r.disabled ? "opacity-50" : "")
      }
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <Verdict r={r} />
          {r.reason && (
            <span className="text-xs text-text-muted truncate" title={r.reason}>
              {r.reason}
            </span>
          )}
        </div>
        <div className="text-xs text-text-muted mt-1 font-mono truncate" title={renderCondition(r)}>
          {renderCondition(r)}
        </div>
      </div>
      <div className="flex flex-col items-end gap-0.5 shrink-0">
        <span className="text-xs text-text-subtle truncate max-w-[10rem]" title={r.name}>
          {r.name}
        </span>
        {(r.priority ?? 0) !== 0 && (
          <span className="text-2xs text-text-subtle tabular-nums">
            p{(r.priority ?? 0) > 0 ? "+" : ""}
            {r.priority}
          </span>
        )}
      </div>
    </div>
  );
}

function FamilyDot({ family }: { family: string }) {
  // Family dots are categorical — three brand anchors give a clean
  // visual partition (cool / warm / accent) without overloading the
  // semantic success/danger colors with category meaning.
  const palette: Record<string, string> = {
    https: "bg-navy-400",
    sql: "bg-butter-500",
    k8s: "bg-rust-500",
  };
  return (
    <span
      className={
        "inline-block w-[6px] h-[6px] rounded-full " + (palette[family] ?? "bg-text-subtle")
      }
      title={family}
    />
  );
}

function Verdict({ r }: { r: RuleSummary }) {
  if (r.approve && r.approve.length > 0) {
    const names = r.approve.map((s) => s.name).join(" → ");
    return (
      <Tag tone="warning" title={names}>
        approve
      </Tag>
    );
  }
  const verdict = r.verdict || "allow";
  const tones: Record<string, Tone> = { allow: "success", deny: "danger" };
  return <Tag tone={tones[verdict] ?? "neutral"}>{verdict}</Tag>;
}

function renderCondition(r: RuleSummary): string {
  const parts: string[] = [];
  if (r.credential) parts.push(`credential = ${r.credential}`);
  if (r.condition) parts.push(r.condition);
  if (parts.length === 0) return "matches every request";
  return parts.join(" · ");
}
