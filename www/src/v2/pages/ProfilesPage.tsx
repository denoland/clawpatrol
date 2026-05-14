import { useEffect, useState } from "react";
import { type Agent, listProfiles, type ProfileInfo } from "../../lib/api";
import { Card } from "../cards/Card";
import { PageHeader } from "../cards/PageHeader";

// Profiles — /api/profiles returns one ProfileInfo per declared
// profile: name, the endpoint set bound to it, an aggregated rule
// count across those endpoints, and the credential names referenced
// by endpoints / tunnels. Devices carry a `profile` field that pins
// each one to a declared profile, so device counts join in
// client-side.
export function ProfilesPage({ agents }: { agents: Agent[] }) {
  const [profiles, setProfiles] = useState<ProfileInfo[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listProfiles()
      .then((p) => setProfiles(p ?? []))
      .catch((e) => setErr(String(e?.message ?? e)))
      .finally(() => setLoading(false));
  }, []);

  const countByProfile = new Map<string, number>();
  for (const a of agents) {
    const key = a.profile || "(default)";
    countByProfile.set(key, (countByProfile.get(key) ?? 0) + 1);
  }

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Profiles"
        subhead="Profiles declared in gateway.hcl. Each lists the endpoints, rules, and credentials it binds — devices inherit one."
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
            {profiles.map((p) => {
              const devices = countByProfile.get(p.name) ?? 0;
              return (
                <li key={p.name} className="px-4 py-3">
                  <div className="flex items-center justify-between">
                    <div className="font-medium">{p.name}</div>
                    <span className="text-xs text-text-muted">read-only</span>
                  </div>
                  <div className="text-xs text-text-muted mt-0.5">
                    {devices} device{devices === 1 ? "" : "s"} · {p.endpoints.length} endpoint
                    {p.endpoints.length === 1 ? "" : "s"} · {p.rule_count} rule
                    {p.rule_count === 1 ? "" : "s"} · {p.credentials.length} credential
                    {p.credentials.length === 1 ? "" : "s"}
                  </div>
                  {p.endpoints.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {p.endpoints.map((ep) => (
                        <span
                          key={ep}
                          className="font-mono text-xs px-1.5 py-0.5 bg-canvas-dark text-text-muted"
                        >
                          {ep}
                        </span>
                      ))}
                    </div>
                  )}
                  {p.credentials.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {p.credentials.map((c) => (
                        <span
                          key={c}
                          className="font-mono text-xs px-1.5 py-0.5 border border-canvas-dark text-text-muted"
                        >
                          {c}
                        </span>
                      ))}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Card>
    </div>
  );
}
