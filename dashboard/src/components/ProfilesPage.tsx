import { useEffect, useState } from "react";
import { listProfileSummaries, type ProfileSummary } from "../lib/api";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";

// ProfilesPage is the V1 dashboard's top-level "where do my agents
// dispatch?" surface — one card per HCL-declared profile, each card
// showing the entity counts (devices, endpoints, credentials,
// tunnels, rules) scoped to that profile.
//
// Replaces the old Devices page in this slot (cl-l6zv); the per-
// device drill-in still lives at `#/device/<ip>`.
export function ProfilesPage() {
  const [profiles, setProfiles] = useState<ProfileSummary[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const list = await listProfileSummaries();
        if (!cancelled) {
          setProfiles(list);
          setErr(null);
        }
      } catch (e: unknown) {
        if (!cancelled) setErr(e instanceof Error ? e.message : String(e));
      }
    }
    load();
    const t = setInterval(load, 5000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  return (
    <Main>
      <PageTitle trail={[{ label: "Claw Patrol", href: "#/" }, { label: "profiles" }]} />
      {err && (
        <div className="bg-canvas border-1.5 border-navy px-5 py-8 text-center text-xs text-rust-700">
          {err}
        </div>
      )}
      {!err && profiles && profiles.length === 0 && (
        <div className="bg-canvas border-1.5 border-navy px-5 py-8 text-center text-xs text-text-subtle">
          no profiles declared — add one to gateway.hcl
        </div>
      )}
      {profiles && profiles.length > 0 && (
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {profiles.map((p) => (
            <ProfileCard key={p.name} profile={p} />
          ))}
        </section>
      )}
    </Main>
  );
}

function ProfileCard({ profile }: { profile: ProfileSummary }) {
  const href = `#/profiles/${encodeURIComponent(profile.name)}`;
  return (
    <a
      href={href}
      className="block bg-canvas border-1.5 border-navy p-4 hover:bg-canvas-muted transition-colors"
    >
      <div className="flex items-baseline justify-between gap-3 mb-3">
        <h2 className="font-mono text-sm font-bold text-navy uppercase tracking-wider truncate">
          {profile.name}
        </h2>
        <span className="text-2xs text-text-subtle">→</span>
      </div>
      <dl className="grid grid-cols-5 gap-1.5">
        <Stat label="Devices" value={profile.devices} />
        <Stat label="Endpoints" value={profile.endpoints} />
        <Stat label="Creds" value={profile.credentials} />
        <Stat label="Tunnels" value={profile.tunnels} />
        <Stat label="Rules" value={profile.rules} />
      </dl>
    </a>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex flex-col items-start gap-0.5">
      <dd className="text-base font-bold text-text tabular-nums">{value}</dd>
      <dt className="font-mono text-2xs uppercase tracking-wider text-text-subtle">{label}</dt>
    </div>
  );
}
