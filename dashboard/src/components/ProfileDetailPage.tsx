import { useEffect, useState } from "react";
import { getProfileDetail, getStatus, type Integration, type ProfileDetail } from "../lib/api";
import { EndpointFlowMap } from "./EndpointFlowMap";
import { IntegrationsCards } from "./IntegrationsCards";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";

// ProfileDetailPage renders one HCL-declared profile: its credentials
// (cards identical to the device-page credentials section, including
// the connection flow on click — IntegrationsCards is reused as-is)
// and one endpoint flow map per endpoint declared in the profile.
//
// Data sources:
//
//   /api/profiles_v2?name=NAME  — endpoint flow shape (rules,
//                                  credential bindings + disambiguators,
//                                  tunnel chain, counts).
//   /api/status?profile=NAME    — credential cards. Server already
//                                  filters to the profile-scoped set
//                                  (mirrors what DevicePage does for
//                                  the per-device credentials row).
//
// Two endpoints because IntegrationsCards expects rich Integration
// rows (OAuth status, slot schema, tailscale auth state, etc.)
// that the profiles_v2 walker doesn't synthesize. Keeping the
// reuse trivially correct beats fattening the new endpoint to
// shadow the existing /api/status payload.
export function ProfileDetailPage({
  name,
  onConnect,
}: {
  name: string;
  onConnect: (id: string) => void;
}) {
  const [detail, setDetail] = useState<ProfileDetail | null>(null);
  const [creds, setCreds] = useState<Integration[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function load() {
    try {
      const [d, c] = await Promise.all([getProfileDetail(name), getStatus(name)]);
      setDetail(d);
      setCreds(c ?? []);
      setErr(null);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  useEffect(() => {
    let cancelled = false;
    async function tick() {
      if (cancelled) return;
      await load();
    }
    tick();
    const t = setInterval(tick, 5000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
    // load is stable enough; name dep covers route change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [name]);

  const trail = [
    { label: "Claw Patrol", href: "#/" },
    { label: "profiles", href: "#/profiles" },
    { label: name },
  ];

  if (err) {
    return (
      <Main>
        <PageTitle trail={trail} />
        <div className="bg-canvas border-1.5 border-navy px-5 py-8 text-center text-xs text-rust-700">
          {err}
        </div>
      </Main>
    );
  }
  if (!detail) {
    return (
      <Main>
        <PageTitle trail={trail} />
        <div className="bg-canvas border-1.5 border-navy px-5 py-8 text-center text-xs text-text-subtle">
          loading…
        </div>
      </Main>
    );
  }

  return (
    <Main>
      <PageTitle trail={trail} />

      <section className="bg-canvas border-1.5 border-navy p-4">
        <div className="grid grid-cols-5 gap-3">
          <Stat label="Devices" value={detail.devices} />
          <Stat label="Endpoints" value={detail.endpoints?.length ?? 0} />
          <Stat label="Credentials" value={detail.credentials} />
          <Stat label="Tunnels" value={detail.tunnels} />
          <Stat label="Rules" value={detail.rules} />
        </div>
      </section>

      <section className="bg-canvas border-1.5 border-navy">
        <div className="flex items-center px-4 py-2.5 bg-navy-100 border-b border-navy gap-2">
          <div className="font-mono text-xs uppercase tracking-wider text-navy font-bold">
            Credentials
          </div>
          <span className="text-2xs text-navy/70">
            for profile <span className="font-mono">{name}</span>
          </span>
        </div>
        <div className="p-3">
          <IntegrationsCards list={creds ?? []} showAll onConnect={onConnect} onRefresh={load} />
        </div>
      </section>

      <section className="bg-canvas border-1.5 border-navy">
        <div className="flex items-center px-4 py-2.5 bg-navy-100 border-b border-navy gap-2">
          <div className="font-mono text-xs uppercase tracking-wider text-navy font-bold">
            Endpoint flow
          </div>
          <span className="text-2xs text-navy/70">
            endpoint → optional tunnel → rules → credential
          </span>
        </div>
        <div className="p-3 space-y-3">
          {detail.endpoints.length === 0 && (
            <div className="px-2 py-4 text-center text-xs text-text-subtle">
              no endpoints declared in this profile
            </div>
          )}
          {detail.endpoints.map((ep) => (
            <EndpointFlowMap key={ep.name} endpoint={ep} />
          ))}
        </div>
      </section>
    </Main>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex flex-col gap-1">
      <div className="text-xl font-bold text-text tabular-nums">{value}</div>
      <div className="font-mono text-2xs uppercase tracking-wider text-text-subtle">{label}</div>
    </div>
  );
}
