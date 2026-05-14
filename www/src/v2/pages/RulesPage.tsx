import { useEffect, useMemo, useState } from "react";
import {
  type Agent,
  type EventRecord,
  getAnalytics,
  getRules,
  listProfiles,
  type ProfileInfo,
  type RuleSummary,
} from "../../lib/api";
import { fmtDateTime } from "../../lib/format";
import { Card } from "../cards/Card";
import { PageHeader } from "../cards/PageHeader";

// Rules — read-only listing per cl-r3e. unclaw's RulesPage edits
// via /rules/new and /rules/:id/edit; those routes are intentionally
// omitted here. clawpatrol's rule model has bare-name + endpoint +
// CEL condition + approve chain instead of unclaw's plugin-scoped
// JSON decisions, so columns reflect clawpatrol's shape.
//
// One profile at a time: the rule set for a complex policy gets
// noisy, so a profile picker (top-right) gates the table to a
// single profile's rules. The selected profile is reflected back
// into the URL hash as `?profile=<name>`, so links into a specific
// view are shareable. Expanding a rule reveals the last five
// decisions it produced; each is a clickable link into the action
// detail page.
export function V2RulesPage({ agents }: { agents: Agent[] }) {
  const [rules, setRules] = useState<RuleSummary[]>([]);
  const [profiles, setProfiles] = useState<ProfileInfo[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<string>(() => readProfileFromHash());

  useEffect(() => {
    Promise.all([getRules(), listProfiles()])
      .then(([r, p]) => {
        setRules(r ?? []);
        setProfiles(p ?? []);
      })
      .catch((e) => setErr(String(e?.message ?? e)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    function onHash() {
      setSelected(readProfileFromHash());
    }
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // All profiles a rule could belong to — `RuleSummary.profile` is
  // empty for some rows; treat those as belonging to "(default)" so
  // they're still reachable through the picker.
  const profileOptions = useMemo(() => {
    const names = new Set<string>();
    for (const p of profiles) names.add(p.name);
    for (const r of rules) names.add(r.profile || "(default)");
    return [...names].sort();
  }, [profiles, rules]);

  // Pick a default selection once data is loaded — first profile in
  // alphabetical order. URL hash wins if it names a known profile.
  useEffect(() => {
    if (!selected && profileOptions.length > 0) {
      const next = profileOptions[0];
      writeProfileToHash(next);
      setSelected(next);
    }
  }, [profileOptions, selected]);

  function setProfile(name: string) {
    writeProfileToHash(name);
    setSelected(name);
  }

  const filtered = useMemo(() => {
    if (!selected) return rules;
    return rules.filter((r) => (r.profile || "(default)") === selected);
  }, [rules, selected]);

  // Group by family within the selected profile.
  const byFamily = new Map<string, RuleSummary[]>();
  for (const r of filtered) {
    const k = r.family || "other";
    if (!byFamily.has(k)) byFamily.set(k, []);
    byFamily.get(k)!.push(r);
  }

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Rules"
        subhead="Rules declared in gateway.hcl. Pick a profile to scope the view; expand any rule to see its last five decisions."
      >
        <label className="flex items-center gap-2 text-xs text-text-muted">
          <span className="uppercase tracking-wider">Profile</span>
          <select
            value={selected}
            onChange={(e) => setProfile(e.target.value)}
            className="border border-canvas-dark bg-canvas-light text-sm px-2 py-1"
          >
            {profileOptions.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </label>
      </PageHeader>

      {loading && <div className="text-sm text-text-muted py-8">Loading rules…</div>}
      {err && (
        <div className="text-sm text-danger-700 bg-danger-100 border border-danger-500 px-3 py-2">
          {err}
        </div>
      )}

      {!loading && !err && filtered.length === 0 && (
        <Card title="Rules">
          <div className="text-sm text-text-muted py-2">No rules declared for this profile.</div>
        </Card>
      )}

      {[...byFamily.entries()].map(([family, rs]) => (
        <Card key={family} title={family.toUpperCase()} count={rs.length} tight>
          <table className="w-full text-sm">
            <thead className="bg-canvas-muted text-left text-text-muted text-xs uppercase tracking-wider">
              <tr>
                <th className="px-4 py-2 font-medium w-6"></th>
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-4 py-2 font-medium">Endpoint</th>
                <th className="px-4 py-2 font-medium">Verdict</th>
                <th className="px-4 py-2 font-medium text-right">Priority</th>
                <th className="px-4 py-2 font-medium">Condition</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-canvas-dark">
              {rs.map((r, idx) => (
                <RuleRow key={`${r.name}-${r.endpoint}-${idx}`} rule={r} agents={agents} />
              ))}
            </tbody>
          </table>
        </Card>
      ))}
    </div>
  );
}

function readProfileFromHash(): string {
  const h = window.location.hash || "";
  const qIdx = h.indexOf("?");
  if (qIdx < 0) return "";
  const params = new URLSearchParams(h.slice(qIdx + 1));
  return params.get("profile") || "";
}

function writeProfileToHash(profile: string) {
  const h = window.location.hash || "";
  const qIdx = h.indexOf("?");
  const path = qIdx < 0 ? h : h.slice(0, qIdx);
  const params = qIdx < 0 ? new URLSearchParams() : new URLSearchParams(h.slice(qIdx + 1));
  if (profile) params.set("profile", profile);
  else params.delete("profile");
  const qs = params.toString();
  const next = qs ? `${path}?${qs}` : path;
  if (next !== h) window.location.hash = next.replace(/^#/, "");
}

function RuleRow({ rule: r, agents }: { rule: RuleSummary; agents: Agent[] }) {
  const [open, setOpen] = useState(false);
  const [events, setEvents] = useState<EventRecord[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadErr, setLoadErr] = useState<string | null>(null);

  const agentLabel = useMemo(() => {
    const m = new Map<string, string>();
    for (const a of agents) m.set(a.ip, a.hostname || a.ip);
    return m;
  }, [agents]);

  async function toggle() {
    const next = !open;
    setOpen(next);
    if (next && events === null && !loading) {
      setLoading(true);
      setLoadErr(null);
      try {
        // Pull last-24h decisions filtered to this rule; limit 5
        // covers the visible request and keeps the server-side
        // sample cheap.
        const resp = await getAnalytics({ range: "24h", rule: r.name, limit: 5 });
        // Server orders by random suffix of action_id — re-sort
        // newest-first for display.
        const sorted = [...(resp.events ?? [])].sort((a, b) => b.ts.localeCompare(a.ts));
        setEvents(sorted.slice(0, 5));
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        setLoadErr(msg);
      } finally {
        setLoading(false);
      }
    }
  }

  return (
    <>
      <tr
        className={`cursor-pointer hover:bg-canvas-muted ${r.disabled ? "opacity-50" : ""}`}
        onClick={toggle}
      >
        <td className="px-4 py-2 text-text-muted text-xs select-none">{open ? "▾" : "▸"}</td>
        <td className="px-4 py-2 font-medium">{r.name}</td>
        <td className="px-4 py-2 font-mono text-xs">{r.endpoint}</td>
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
      {open && (
        <tr className="bg-canvas-muted/50">
          <td colSpan={6} className="px-4 py-3">
            {loading && <div className="text-xs text-text-muted">Loading decisions…</div>}
            {loadErr && <div className="text-xs text-danger-700">Failed to load: {loadErr}</div>}
            {!loading && !loadErr && events && events.length === 0 && (
              <div className="text-xs text-text-muted">No decisions in the last 24 hours.</div>
            )}
            {!loading && !loadErr && events && events.length > 0 && (
              <div className="text-xs">
                <div className="text-text-muted uppercase tracking-wider mb-1">
                  Last {events.length} decision{events.length === 1 ? "" : "s"}
                </div>
                <ul className="divide-y divide-canvas-dark border border-canvas-dark bg-canvas-light">
                  {events.map((e) => (
                    <li
                      key={(e.id ?? "") + e.ts}
                      className="px-3 py-2 flex items-center gap-3 hover:bg-canvas-muted cursor-pointer"
                      onClick={(ev) => {
                        ev.stopPropagation();
                        if (e.id) {
                          window.location.hash = `#/v2/actions/${encodeURIComponent(e.id)}`;
                        }
                      }}
                    >
                      <span className="font-mono text-text-muted whitespace-nowrap">
                        {fmtDateTime(e.ts)}
                      </span>
                      <span className="text-text-muted truncate max-w-[140px]">
                        {e.agent_ip ? (agentLabel.get(e.agent_ip) ?? e.agent_ip) : "—"}
                      </span>
                      <Verdict v={e.action ?? "—"} />
                      <span className="truncate flex-1">
                        <span className="font-mono text-text-muted mr-1">{e.method}</span>
                        {e.endpoint || e.host}
                        {e.path}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

function Verdict({ v }: { v: string }) {
  const palette =
    v === "allow" || v === "approved"
      ? "bg-success-100 text-success-700"
      : v === "deny" || v === "denied"
        ? "bg-danger-100 text-danger-700"
        : "bg-canvas-dark text-text-muted";
  return <span className={`text-xs px-1.5 py-0.5 rounded-full ${palette}`}>{v}</span>;
}
