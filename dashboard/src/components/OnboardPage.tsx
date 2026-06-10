import { useEffect, useState } from "react";
import { Button } from "./Button";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";

export function OnboardPage({ code }: { code: string }) {
  const [status, setStatus] = useState<"idle" | "approving" | "approved" | "error">("idle");
  const [err, setErr] = useState("");
  const [info, setInfo] = useState<{
    user_code?: string;
    approved?: boolean;
    ca_fingerprint?: string;
    profiles?: string[];
    suggested_profile?: string;
  } | null>(null);
  const [profile, setProfile] = useState("");
  const [assigned, setAssigned] = useState("");

  useEffect(() => {
    fetch("/api/onboard/lookup?code=" + encodeURIComponent(code))
      .then((r) => (r.ok ? r.json() : Promise.reject(r.statusText)))
      .then((d) => {
        setInfo(d);
        setProfile(d.suggested_profile || "");
        // For an already-approved code the suggestion IS the
        // assignment (the gateway stores the final choice).
        if (d.approved) setAssigned(d.suggested_profile || "");
      })
      .catch((e) => setErr(String(e)));
  }, [code]);

  async function approve() {
    setStatus("approving");
    try {
      let url = "/api/onboard/approve?code=" + encodeURIComponent(code);
      if (profile) url += "&profile=" + encodeURIComponent(profile);
      const r = await fetch(url, { method: "POST" });
      if (!r.ok) {
        setErr(await r.text());
        setStatus("error");
        return;
      }
      const d = await r.json().catch(() => ({}));
      setAssigned(d.profile || profile);
      setStatus("approved");
    } catch (e) {
      setErr(String(e));
      setStatus("error");
    }
  }

  const profiles = info?.profiles ?? [];

  return (
    <Main centered>
      <PageTitle trail={[{ label: "Add device" }]} />

      <div className="flex-1 flex items-center justify-center py-8">
        <div className="w-full max-w-[30rem] space-y-5">
          {!info && !err && <div className="text-xs text-text-muted">loading…</div>}
          {err && <div className="text-xs text-danger-500">{err}</div>}

          {info && (
            <div className="bg-canvas border-1.5 border-navy p-6 space-y-4">
              <div>
                <div className="font-mono text-2xs uppercase tracking-wider text-text-subtle">
                  code from CLI
                </div>
                <div className="font-mono text-3xl tracking-[.18em] text-text mt-1">
                  {info.user_code || code}
                </div>
              </div>

              <div className="text-xs text-text-muted">
                only approve if you typed this code on the new machine.
              </div>

              {!info.approved && status !== "approved" && profiles.length > 0 && (
                <div>
                  <label className="font-mono text-2xs uppercase tracking-wider text-text-subtle block">
                    profile
                  </label>
                  {profiles.length === 1 ? (
                    <div className="font-mono text-sm text-text mt-1">{profiles[0]}</div>
                  ) : (
                    <select
                      value={profile}
                      onChange={(e) => setProfile(e.target.value)}
                      disabled={status === "approving"}
                      className="mt-1 w-full font-mono text-sm text-text bg-canvas border-1.5 border-navy px-2 py-1.5"
                    >
                      {profiles.map((p) => (
                        <option key={p} value={p}>
                          {p}
                        </option>
                      ))}
                    </select>
                  )}
                </div>
              )}

              {info.ca_fingerprint && (
                <details className="text-[0.6875rem] text-[#737373]">
                  <summary className="cursor-pointer hover:text-[#171717]">
                    CA fingerprint — should match `CA fingerprint:` line on the CLI
                  </summary>
                  <div className="font-mono text-2xs mt-1 break-all text-[#525252] select-all">
                    {info.ca_fingerprint}
                  </div>
                </details>
              )}

              {status === "idle" && !info.approved && (
                <Button size="md" onClick={approve} className="w-full">
                  approve
                </Button>
              )}
              {status === "approving" && <div className="text-xs text-text-muted">approving…</div>}
              {(status === "approved" || info.approved) && (
                <div className="text-xs text-success-600">
                  ✓ approved
                  {assigned ? (
                    <>
                      {" — profile "}
                      <span className="font-mono">{assigned}</span>
                    </>
                  ) : null}
                  {" — return to the CLI on the new device"}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </Main>
  );
}
