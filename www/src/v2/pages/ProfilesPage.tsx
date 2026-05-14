import { useEffect, useState } from "react";
import { type Agent, listProfiles } from "../../lib/api";
import { Card } from "../cards/Card";
import { PageHeader } from "../cards/PageHeader";

// Profiles — clawpatrol exposes profile names via /api/profiles
// (a flat string[]) and agents carry a `profile` field that pins
// each device to one. There's no named-profile object with
// integrations / session counts / approver defaults the way unclaw
// has, so the page is necessarily skinnier than unclaw's.
//
// Gap: unclaw's per-profile workspace (integrations list,
// default LLM/Human approver pickers, session count) requires
// profile metadata that clawpatrol's read API doesn't surface.
// Renders as empty-state.
export function ProfilesPage({ agents }: { agents: Agent[] }) {
  const [profiles, setProfiles] = useState<string[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listProfiles()
      .then((p) => setProfiles(p ?? []))
      .catch((e) => setErr(String(e?.message ?? e)))
      .finally(() => setLoading(false));
  }, []);

  // Build a count of agents per profile so the empty-named-profile
  // list still has something concrete to show.
  const countByProfile = new Map<string, number>();
  for (const a of agents) {
    const key = a.profile || "(default)";
    countByProfile.set(key, (countByProfile.get(key) ?? 0) + 1);
  }

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Profiles"
        subhead="Profiles declared in gateway.hcl. Devices inherit a profile; profile metadata (integrations, default approvers) isn't exposed by clawpatrol's API."
      />

      {loading && <div className="text-sm text-text-muted py-8">Loading profiles…</div>}
      {err && (
        <div className="text-sm text-danger-700 bg-danger-100 border border-danger-500 px-3 py-2">
          {err}
        </div>
      )}

      <Card title="Declared profiles" count={profiles.length} tight>
        {profiles.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-text-muted">No profiles declared.</div>
        ) : (
          <ul className="divide-y divide-canvas-dark">
            {profiles.map((p) => (
              <li key={p} className="px-4 py-3 flex items-center justify-between">
                <div>
                  <div className="font-medium">{p}</div>
                  <div className="text-xs text-text-muted mt-0.5">
                    {countByProfile.get(p) ?? 0} device
                    {(countByProfile.get(p) ?? 0) === 1 ? "" : "s"}
                  </div>
                </div>
                <span className="text-xs text-text-muted">read-only</span>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Gap vs unclaw">
        <div className="text-sm text-text-muted space-y-1">
          <p>
            unclaw's <code className="font-mono text-xs">/api/profiles</code> returns objects with
            integration lists, session counts, and default LLM / Human approver pointers — the
            profile page in unclaw is effectively a profile workspace.
          </p>
          <p>
            clawpatrol's <code className="font-mono text-xs">/api/profiles</code> returns a flat
            string list. Per cl-r3e we don't extend the backend, so this view is intentionally
            spare.
          </p>
        </div>
      </Card>
    </div>
  );
}
