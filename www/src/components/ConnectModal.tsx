import { useEffect, useRef, useState } from "react";
import { oauthDevicePoll, oauthExchange, oauthStart, type OAuthStartResp } from "../lib/api";

export function ConnectModal({
  id,
  profile,
  onClose,
  onDone,
}: {
  id: string;
  profile?: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [start, setStart] = useState<OAuthStartResp | null>(null);
  const [code, setCode] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  useEffect(() => {
    oauthStart(id, profile)
      .then((r) => {
        setStart(r);
        if (r.flow === "device") {
          window.open(r.verification_uri, "_blank", "noopener,noreferrer");
        } else {
          window.open((r as any).auth_url, "_blank", "noopener,noreferrer");
        }
      })
      .catch((e: Error) => setErr(String(e.message ?? e)));
  }, [id, profile]);

  // Stable ref to onDone — parent re-renders (App refreshes integrations
  // every 3s) reset the lambda otherwise, killing the polling interval
  // before its 5s tick can fire.
  const onDoneRef = useRef(onDone);
  onDoneRef.current = onDone;

  useEffect(() => {
    if (!start || start.flow !== "device") return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    let intervalSec = start.interval || 5;
    // RFC 8628: client must respect the `interval` field returned on
    // slow_down. Reschedule via setTimeout instead of fixed interval
    // so each tick uses the latest cadence GitHub asked for.
    const tick = async () => {
      if (cancelled) return;
      try {
        const r = await oauthDevicePoll(start.state);
        if (cancelled) return;
        if (r.connected) {
          setDone(true);
          setTimeout(() => onDoneRef.current(), 800);
          return;
        }
        if (r.interval && r.interval > intervalSec) {
          intervalSec = r.interval;
        }
        if (r.error && r.error !== "authorization_pending" && r.error !== "slow_down") {
          setErr(`${r.error}: ${r.detail || ""}`);
          return;
        }
      } catch (_) {
        /* transient — keep polling */
      }
      if (!cancelled) timer = setTimeout(tick, intervalSec * 1000);
    };
    timer = setTimeout(tick, intervalSec * 1000);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [start]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!start || start.flow === "device") return;
    setBusy(true);
    setErr(null);
    try {
      await oauthExchange(start.state, code);
      setDone(true);
      setTimeout(onDone, 800);
    } catch (e: any) {
      setErr(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 bg-black/30 flex items-center justify-center z-50"
      onClick={onClose}
    >
      <div
        className="bg-white border border-[#e5e5e5] rounded-md p-5 w-[520px] shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="text-[11px] uppercase tracking-[.12em] text-[#a3a3a3] mb-1">
          CONNECT {id}
        </div>
        {start && "owner" in start && start.owner && (
          <div className="text-[11px] text-[#737373] mb-3">
            for <span className="text-[#171717] font-semibold">{start.owner}</span>
          </div>
        )}
        {done ? (
          <div className="py-6 text-center">
            <div className="text-[24px] mb-2">✓</div>
            <div className="text-[12px] text-[#171717]">connected</div>
          </div>
        ) : !start ? (
          <div className="text-[12px] text-[#737373]">opening browser…</div>
        ) : start.flow === "device" ? (
          <div className="space-y-3">
            <div className="text-[11px] text-[#737373] leading-relaxed">
              browser opened to <code className="text-[#171717]">{start.verification_uri}</code>. enter this code:
            </div>
            <div className="font-mono text-[28px] tracking-[.18em] text-[#171717] text-center py-3 bg-[#fafafa] border border-[#e5e5e5] rounded select-all">
              {start.user_code}
            </div>
            <div className="text-[11px] text-[#a3a3a3] text-center">waiting for approval…</div>
            {err && <div className="text-[11px] text-red-600 break-all">{err}</div>}
            <div className="flex justify-end">
              <button
                type="button"
                onClick={onClose}
                className="text-[11px] px-3 py-1.5 border border-[#e5e5e5] text-[#737373] rounded hover:border-[#a3a3a3]"
              >
                cancel
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="text-[11px] text-[#737373] leading-relaxed">
              browser opened. log in, then paste the code from the redirect URL bar (after{" "}
              <code className="text-[#171717]">?code=</code>) here:
            </div>
            <form onSubmit={submit}>
              <input
                type="text"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="paste code here"
                className="w-full text-[12px] border border-[#e5e5e5] rounded px-2 py-2 focus:outline-none focus:border-[#171717] font-mono transition-colors"
                autoFocus
              />
              {err && <div className="text-[11px] text-red-600 mt-2 break-all">{err}</div>}
              <div className="flex gap-2 mt-3 justify-end">
                <button
                  type="button"
                  onClick={onClose}
                  className="text-[11px] px-3 py-1.5 border border-[#e5e5e5] text-[#737373] rounded hover:border-[#a3a3a3]"
                >
                  cancel
                </button>
                <button
                  type="submit"
                  disabled={busy || !code}
                  className="text-[11px] px-3 py-1.5 bg-[#171717] text-white rounded disabled:bg-[#a3a3a3]"
                >
                  {busy ? "exchanging…" : "connect"}
                </button>
              </div>
            </form>
          </div>
        )}
      </div>
    </div>
  );
}
