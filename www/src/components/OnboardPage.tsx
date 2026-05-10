import { useEffect, useState } from "react";

export function OnboardPage({ code, onBack }: { code: string; onBack: () => void }) {
  const [status, setStatus] = useState<"idle" | "approving" | "approved" | "error">("idle");
  const [err, setErr] = useState("");
  const [info, setInfo] = useState<{ user_code?: string; approved?: boolean } | null>(null);

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
    <main className="mx-auto w-full max-w-[640px] px-6 py-12 space-y-6">
      <button onClick={onBack} className="text-[11px] text-[#737373] hover:text-[#171717]">
        ← back
      </button>
      <h1 className="font-serif text-[36px] leading-none tracking-tight text-[#171717]">
        add device
      </h1>

      {!info && !err && <div className="text-[12px] text-[#737373]">loading…</div>}
      {err && <div className="text-[12px] text-[#dc2626]">{err}</div>}

      {info && (
        <div className="bg-white border border-[#e5e5e5] rounded p-6 space-y-4">
          <div>
            <div className="text-[10px] uppercase tracking-[.12em] text-[#a3a3a3]">
              code from CLI
            </div>
            <div className="font-mono text-[28px] tracking-[.18em] text-[#171717] mt-1">
              {info.user_code || code}
            </div>
          </div>

          <div className="text-[11px] text-[#737373]">
            only approve if you typed this code on the new machine.
          </div>

          {status === "idle" && !info.approved && (
            <button
              onClick={approve}
              className="w-full px-4 py-2 bg-[#171717] text-white rounded hover:bg-[#000] text-[13px]"
            >
              approve
            </button>
          )}
          {status === "approving" && <div className="text-[12px] text-[#737373]">approving…</div>}
          {(status === "approved" || info.approved) && (
            <div className="text-[12px] text-[#16a34a]">
              ✓ approved — return to the CLI on the new device
            </div>
          )}
        </div>
      )}
    </main>
  );
}
