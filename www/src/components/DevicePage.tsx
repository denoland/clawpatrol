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
import { Sparkline } from "./Sparkline";
import { LiveRequests } from "./LiveRequests";
import { RulesPanel } from "./RulesPanel";
import { IntegrationsCards } from "./IntegrationsCards";
import { SessionsTable } from "./SessionsTable";

export function DevicePage({
  ip,
  agents,
  integrations,
  readOnlyConfig,
  onBack,
  onConnect,
  onRefresh,
}: {
  ip: string;
  agents: Agent[];
  integrations: Integration[];
  readOnlyConfig?: boolean;
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
      .then(setProfiles)
      .catch(() => setProfiles([]));
  }, []);
  const devProfile = a?.profile;
  useEffect(() => {
    if (!devProfile) {
      setProfileCreds(null);
      return;
    }
    getStatus(devProfile)
      .then(setProfileCreds)
      .catch(() => setProfileCreds(null));
    // Re-fetch whenever the parent's integrations list changes too —
    // OAuth modal calls onRefresh on success, which updates parent state
    // but otherwise this effect would stay stale and the card wouldn't
    // flip to "connected" until the next manual profile change.
  }, [devProfile, integrations]);
  if (!a) {
    return (
      <main className="mx-auto w-full max-w-[1100px] px-4 sm:px-6 py-5">
        <nav className="text-[13px] text-[#a3a3a3] flex items-center gap-1.5 mb-3">
          <a href="#/" className="hover:text-[#171717]">
            clawpatrol
          </a>
          <span>/</span>
          <span className="text-[#525252]">{ip}</span>
        </nav>
        <div className="bg-white border border-[#e5e5e5] rounded px-5 py-8 text-center text-[12px] text-[#a3a3a3]">
          no agent with ip {ip}
        </div>
      </main>
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
    <main className="mx-auto w-full max-w-[1100px] px-4 sm:px-6 py-5 space-y-5">
      <div className="flex items-center justify-between">
        <nav className="text-[13px] text-[#a3a3a3] flex items-center gap-1.5">
          <a href="#/" className="hover:text-[#171717]">
            clawpatrol
          </a>
          <span>/</span>
          <span className="text-[#525252]">{dev.hostname || dev.ip}</span>
        </nav>
        <div className="flex items-center gap-2">
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
            className="w-[36px] h-[36px] rounded-full border border-[#e5e5e5] text-[#525252] flex items-center justify-center hover:border-[#171717] hover:text-[#171717] transition-colors"
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
            className="w-[36px] h-[36px] rounded-full border border-[#e5e5e5] text-[#525252] flex items-center justify-center hover:border-[#dc2626] hover:text-[#dc2626] transition-colors"
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
        </div>
      </div>

      {/* device header card */}
      <section className="bg-white border border-[#e5e5e5] rounded">
        <div className="flex items-center gap-3 px-5 py-4 border-b border-[#e5e5e5]">
          <DeviceIcon
            os={a.os}
            hostname={a.hostname}
            ua={a.ua}
            className="w-[18px] h-[18px] text-[#525252]"
          />
          <div className="min-w-0">
            <div className="text-[15px] font-semibold text-[#171717] truncate">
              {a.hostname || a.ip}
            </div>
            <div className="text-[11px] text-[#737373] truncate">
              {a.profile || "—"} ·{" "}
              {[a.external_ipv4, a.external_ipv6].filter(Boolean).join(" / ") || a.ip}
              {a.os && (
                <>
                  {" "}
                  · <span className="uppercase tracking-[.08em]">{a.os}</span>
                </>
              )}
            </div>
          </div>
          <div className="ml-auto flex items-center gap-3">
            <Sparkline data={a.activity} width={160} height={26} />
            <div className="text-right">
              <div className="text-[10px] uppercase tracking-[.09em] text-[#a3a3a3]">TRAFFIC</div>
              <div className="text-[12px] tabular-nums">{fmtBytes(total)}</div>
            </div>
            <div className="text-right">
              <div className="text-[10px] uppercase tracking-[.09em] text-[#a3a3a3]">REQS</div>
              <div className="text-[12px] tabular-nums">{a.reqs}</div>
            </div>
          </div>
        </div>
      </section>

      {/* agents (sessions) running on this device */}
      <SessionsTable sessions={a.sessions ?? []} />

      {/* live request stream filtered by this device */}
      <LiveRequests agentIP={a.ip} height="360px" />

      {/* integrations management for this user */}
      <IntegrationsCards list={allForUser} onConnect={onConnect} onRefresh={onRefresh} />

      {/* rules — per-device scope (with global rules layered in) */}
      <RulesPanel deviceIP={a.ip} profile={a.profile} readOnly={readOnlyConfig} />
    </main>
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
        className="w-[36px] h-[36px] rounded-full border border-[#e5e5e5] text-[#525252] flex items-center justify-center hover:border-[#171717] hover:text-[#171717] transition-colors disabled:opacity-50"
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
        <div className="absolute right-0 top-[calc(100%+6px)] z-20 min-w-[200px] bg-white border border-[#e5e5e5] rounded shadow-lg py-1">
          <div className="px-3 py-1.5 text-[10px] uppercase tracking-[.12em] text-[#a3a3a3] border-b border-[#f5f5f5]">
            choose profile
          </div>
          {profiles.length === 0 ? (
            <div className="px-3 py-2 text-[11px] text-[#a3a3a3]">no profiles</div>
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
                    "w-full text-left px-3 py-1.5 text-[12px] flex items-center gap-2 hover:bg-[#f5f5f5] " +
                    (active ? "text-[#171717] font-medium" : "text-[#525252]")
                  }
                >
                  <span
                    className={
                      "w-[6px] h-[6px] rounded-full flex-shrink-0 " +
                      (active ? "bg-[#22c55e]" : "border border-[#e5e5e5]")
                    }
                  />
                  <span className="truncate">{p}</span>
                </button>
              );
            })
          )}
        </div>
      )}
      {err && <div className="text-[10px] text-red-600 mt-1">{err}</div>}
    </div>
  );
}
