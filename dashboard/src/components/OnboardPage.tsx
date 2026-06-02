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
  } | null>(null);

  useEffect(() => {
    fetch("/api/onboard/lookup?code=" + encodeURIComponent(code))
      .then((r) => (r.ok ? r.json() : Promise.reject(r.statusText)))
      .then((d) => setInfo(d))
      .catch((e) => setErr(String(e)));
  }, [code]);

  async function approve() {
    setStatus("approving");
    try {
      const r = await fetch("/api/onboard/approve?code=" + encodeURIComponent(code), {
        method: "POST",
      });
      if (!r.ok) {
        setErr(await r.text());
        setStatus("error");
        return;
      }
      setStatus("approved");
    } catch (e) {
      setErr(String(e));
      setStatus("error");
    }
  }

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
                  ✓ approved — return to the CLI on the new device
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </Main>
  );
}
