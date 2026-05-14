import { useEffect, useState } from "react";
import { getRules, type RuleSummary } from "../../lib/api";
import { Card } from "../cards/Card";
import { PageHeader } from "../cards/PageHeader";

// Rules — read-only listing per cl-r3e. unclaw's RulesPage edits
// via /rules/new and /rules/:id/edit; those routes are intentionally
// omitted here. clawpatrol's rule model has bare-name + endpoint +
// CEL condition + approve chain instead of unclaw's plugin-scoped
// JSON decisions, so columns reflect clawpatrol's shape.
export function V2RulesPage() {
  const [rules, setRules] = useState<RuleSummary[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getRules()
      .then((r) => setRules(r ?? []))
      .catch((e) => setErr(String(e?.message ?? e)))
      .finally(() => setLoading(false));
  }, []);

  // Group by family for readability — HTTPS vs SQL vs k8s vs other.
  const byFamily = new Map<string, RuleSummary[]>();
  for (const r of rules) {
    const k = r.family || "other";
    if (!byFamily.has(k)) byFamily.set(k, []);
    byFamily.get(k)!.push(r);
  }

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Rules"
        subhead="Rules declared in gateway.hcl. Editing happens by pushing HCL — this view is read-only."
      />

      {loading && <div className="text-sm text-text-muted py-8">Loading rules…</div>}
      {err && (
        <div className="text-sm text-danger-700 bg-danger-100 border border-danger-500 px-3 py-2">
          {err}
        </div>
      )}

      {!loading && !err && rules.length === 0 && (
        <Card title="Rules">
          <div className="text-sm text-text-muted py-2">No rules declared.</div>
        </Card>
      )}

      {[...byFamily.entries()].map(([family, rs]) => (
        <Card key={family} title={family.toUpperCase()} count={rs.length} tight>
          <table className="w-full text-sm">
            <thead className="bg-canvas-muted text-left text-text-muted text-xs uppercase tracking-wider">
              <tr>
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-4 py-2 font-medium">Endpoint</th>
                <th className="px-4 py-2 font-medium">Profile</th>
                <th className="px-4 py-2 font-medium">Verdict</th>
                <th className="px-4 py-2 font-medium text-right">Priority</th>
                <th className="px-4 py-2 font-medium">Condition</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-canvas-dark">
              {rs.map((r, idx) => (
                <tr
                  key={`${r.name}-${r.endpoint}-${idx}`}
                  className={r.disabled ? "opacity-50" : ""}
                >
                  <td className="px-4 py-2 font-medium">{r.name}</td>
                  <td className="px-4 py-2 font-mono text-xs">{r.endpoint}</td>
                  <td className="px-4 py-2 text-text-muted">{r.profile || "—"}</td>
                  <td className="px-4 py-2">
                    {r.verdict ? (
                      <Verdict v={r.verdict} />
                    ) : r.approve && r.approve.length > 0 ? (
                      <span className="text-xs px-1.5 py-0.5 rounded-full bg-butter-100 text-butter-900">
                        approve · {r.approve.map((s) => s.name).join(" → ")}
                      </span>
                    ) : (
                      <span className="text-xs text-text-muted">—</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-right">{r.priority ?? 0}</td>
                  <td className="px-4 py-2 font-mono text-[11px] text-text-muted break-all max-w-md">
                    {r.condition || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      ))}
    </div>
  );
}

function Verdict({ v }: { v: string }) {
  const palette =
    v === "allow"
      ? "bg-success-100 text-success-700"
      : v === "deny"
        ? "bg-danger-100 text-danger-700"
        : "bg-canvas-dark text-text-muted";
  return <span className={`text-xs px-1.5 py-0.5 rounded-full ${palette}`}>{v}</span>;
}
