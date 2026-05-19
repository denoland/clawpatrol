import { useEffect, useMemo, useRef, useState } from "react";
import {
  deleteAgent,
  getStatus,
  listProfiles,
  setDeviceProfile,
  type Agent,
  type Integration,
} from "../lib/api";
import { fmtBytes } from "../lib/format";
import { DeviceIcon } from "./Logos";
import { IntegrationsCards } from "./IntegrationsCards";
import { LiveRequests } from "./LiveRequests";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";
import { RulesPanel } from "./RulesPanel";
import { SessionsTable } from "./SessionsTable";
import { Sparkline } from "./Sparkline";

export function DevicePage({
  ip,
  agents,
  integrations,
  configFile,
  onBack,
  onConnect,
  onRefresh,
}: {
  ip: string;
  agents: Agent[];
  integrations: Integration[];
  configFile: string;
  onBack: () => void;
  onConnect: (id: string) => void;
  onRefresh: () => void;
}) {
  const a = useMemo(() => agents.find((x) => x.ip === ip) ?? null, [agents, ip]);
  const [profiles, setProfiles] = useState<string[]>([]);
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileErr, setProfileErr] = useState<string | null>(null);
  // Per-profile credential list — server-filters to only the
  // credentials referenced by endpoints in this device's profile,
  // so a "writer" device doesn't see the readonly's pg-cred and vice
  // versa. Falls back to the parent's full list for the no-profile
  // case (legacy single-tenant configs).
  const [profileCreds, setProfileCreds] = useState<Integration[] | null>(null);
  useEffect(() => {
    listProfiles()
      .then((p) => setProfiles(p ?? []))
      .catch(() => setProfiles([]));
  }, []);
  const devProfile = a?.profile;
  useEffect(() => {
    if (!devProfile) {
      setProfileCreds(null);
      return;
    }
    getStatus(devProfile)
      .then((c) => setProfileCreds(c ?? []))
      .catch(() => setProfileCreds(null));
    // Re-fetch whenever the parent's integrations list changes too —
    // OAuth modal calls onRefresh on success, which updates parent state
    // but otherwise this effect would stay stale and the card wouldn't
    // flip to "connected" until the next manual profile change.
  }, [devProfile, integrations]);
  if (!a) {
    return (
      <Main>
        <PageTitle trail={[{ label: "clawpatrol", href: "#/" }, { label: ip }]} />
        <div className="bg-canvas-light border-1.5 border-navy px-5 py-8 text-center text-xs text-text-subtle">
          no agent with ip {ip}
        </div>
      </Main>
    );
  }

  const dev = a;
  const total = dev.bytes_in + dev.bytes_out;
  const allForUser = profileCreds ?? integrations;

  async function remove() {
    if (
      !confirm(
        `Remove ${dev.hostname || dev.ip} from clawpatrol?\n\nThis clears the device's tracking + owner mapping. Tailscale node stays — remove from admin console if you want a hard kick.`,
      )
    )
      return;
    try {
      await deleteAgent(dev.ip);
      onBack();
      onRefresh();
    } catch (e: any) {
      alert("delete failed: " + (e?.message ?? e));
    }
  }

  return (
    <Main>
      <PageTitle
        trail={[{ label: "clawpatrol", href: "#/" }, { label: dev.hostname || dev.ip }]}
        actions={
          <>
            <ProfilePicker
              current={a.profile ?? ""}
              profiles={profiles}
              saving={profileSaving}
              err={profileErr}
              onPick={async (next) => {
                if (!next || next === a.profile) return;
                setProfileSaving(true);
                setProfileErr(null);
                try {
                  await setDeviceProfile(a.ip, next);
                  onRefresh();
                } catch (err: any) {
                  setProfileErr(String(err.message ?? err));
                } finally {
                  setProfileSaving(false);
                }
              }}
            />
            <a
              href={`#/analytics/${encodeURIComponent(ip)}`}
              title="analytics"
              className="w-[36px] h-[36px] rounded-full border border-canvas-dark text-text-muted flex items-center justify-center hover:border-text hover:text-text transition-colors"
            >
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M3 3v18h18" />
                <path d="m7 16 4-8 4 4 4-6" />
              </svg>
            </a>
            <button
              type="button"
              onClick={remove}
              title="forget this device"
              className="w-[36px] h-[36px] rounded-full border border-canvas-dark text-text-muted flex items-center justify-center hover:border-danger-500 hover:text-danger-500 transition-colors"
            >
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M3 6h18" />
                <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
                <path d="M10 11v6" />
                <path d="M14 11v6" />
              </svg>
            </button>
          </>
        }
      />

      {/* device header card */}
      <section className="bg-canvas-light border-1.5 border-navy">
        <div className="flex items-center gap-3 px-5 py-4">
          <DeviceIcon
            os={a.os}
            hostname={a.hostname}
            ua={a.ua}
            className="w-[18px] h-[18px] text-text-muted"
          />
          <div className="min-w-0">
            <div className="text-base font-semibold text-text truncate">{a.hostname || a.ip}</div>
            <div className="text-xs text-text-muted truncate">
              {a.profile || "—"} ·{" "}
              {[a.external_ipv4, a.external_ipv6].filter(Boolean).join(" / ") || a.ip}
              {a.os && (
                <>
                  {" "}
                  · <span className="font-mono uppercase tracking-wider">{a.os}</span>
                </>
              )}
            </div>
          </div>
          <div className="ml-auto flex items-center gap-3">
            <Sparkline data={a.activity} width={160} height={26} />
            <div className="text-right">
              <div className="font-mono text-2xs uppercase tracking-wider text-text-subtle">
                Traffic
              </div>
              <div className="text-xs tabular-nums">{fmtBytes(total)}</div>
            </div>
            <div className="text-right">
              <div className="font-mono text-2xs uppercase tracking-wider text-text-subtle">
                Reqs
              </div>
              <div className="text-xs tabular-nums">{a.reqs}</div>
            </div>
          </div>
        </div>
      </section>

      {/* agents (sessions) running on this device */}
      <SessionsTable sessions={a.sessions ?? []} />

      {/* live request stream filtered by this device */}
      <LiveRequests agentIP={a.ip} height="360px" />

      {/* credentials for this device's profile — header makes the
          profile→credentials linkage explicit and points operators at
          gateway.hcl since the dashboard is read-only for declarations. */}
      <section className="bg-canvas-light border-1.5 border-navy">
        <div className="flex items-center px-4 py-2.5 bg-navy-100 border-b border-navy gap-2">
          <div className="font-mono text-xs uppercase tracking-wider text-navy font-bold">
            Credentials
          </div>
          {a.profile && (
            <span className="text-2xs text-navy/70">
              for profile <span className="font-mono">{a.profile}</span>
            </span>
          )}
          <span className="ml-auto text-2xs text-navy/70">
            declared in <span className="font-mono">{configFile}</span>
          </span>
        </div>
        <div className="p-3">
          <IntegrationsCards list={allForUser} onConnect={onConnect} onRefresh={onRefresh} />
        </div>
      </section>

      {/* rules — per-device scope (with global rules layered in) */}
      <RulesPanel deviceIP={a.ip} profile={a.profile} />
    </Main>
  );
}

function ProfilePicker({
  current,
  profiles,
  saving,
  err,
  onPick,
}: {
  current: string;
  profiles: string[];
  saving: boolean;
  err: string | null;
  onPick: (next: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    function onDoc(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);
  const disabled = saving || profiles.length === 0;
  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        disabled={disabled}
        onClick={() => setOpen((v) => !v)}
        title={`profile: ${current || "—"}`}
        className="w-[36px] h-[36px] rounded-full border border-canvas-dark text-text-muted flex items-center justify-center hover:border-text hover:text-text transition-colors disabled:opacity-50"
      >
        <svg
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M12 2 2 7l10 5 10-5-10-5z" />
          <path d="M2 17l10 5 10-5" />
          <path d="M2 12l10 5 10-5" />
        </svg>
      </button>
      {open && (
        <div className="absolute right-0 top-[calc(100%+6px)] z-20 min-w-[200px] bg-canvas-light border-1.5 border-navy rounded shadow-lg py-1">
          <div className="font-mono px-3 py-1.5 text-2xs uppercase tracking-wider text-text-subtle border-b border-canvas-muted">
            choose profile
          </div>
          {profiles.length === 0 ? (
            <div className="px-3 py-2 text-xs text-text-subtle">no profiles</div>
          ) : (
            profiles.map((p) => {
              const active = p === current;
              return (
                <button
                  key={p}
                  type="button"
                  onClick={() => {
                    onPick(p);
                    setOpen(false);
                  }}
                  className={
                    "w-full text-left px-3 py-1.5 text-xs flex items-center gap-2 hover:bg-canvas-muted " +
                    (active ? "text-text font-medium" : "text-text-muted")
                  }
                >
                  <span
                    className={
                      "w-[6px] h-[6px] rounded-full shrink-0 " +
                      (active ? "bg-success-500" : "border border-canvas-dark")
                    }
                  />
                  <span className="truncate">{p}</span>
                </button>
              );
            })
          )}
        </div>
      )}
      {err && <div className="text-2xs text-rust-700 mt-1">{err}</div>}
    </div>
  );
}
