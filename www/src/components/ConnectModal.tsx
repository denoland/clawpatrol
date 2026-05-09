import { useEffect, useRef, useState } from "react";
import {
  oauthDevicePoll,
  oauthExchange,
  oauthStart,
  type OAuthIntegrationUI,
  type OAuthStartResp,
} from "../lib/api";

export function ConnectModal({
  id,
  oauth,
  profile,
  onClose,
  onDone,
}: {
  id: string;
  oauth?: OAuthIntegrationUI | null;
  profile?: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [start, setStart] = useState<OAuthStartResp | null>(null);
  const [code, setCode] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  // The picker only appears when the plugin declared optional scopes.
  // Plugins that don't surface a picker fall straight through to the
  // OAuth start (started=true on mount).
  const optionalGroups = oauth?.optional_scopes ?? [];
  const baseScopes = oauth?.base_scopes ?? [];
  const showsScopePicker = optionalGroups.length > 0;
  const [started, setStarted] = useState(!showsScopePicker);
  const [extras, setExtras] = useState<Set<string>>(() => new Set());
  const baseSet = new Set(baseScopes);

  useEffect(() => {
    if (!started) return;
    const extraList = showsScopePicker ? Array.from(extras) : undefined;
    oauthStart(id, profile, extraList)
      .then((r) => {
        setStart(r);
        if (r.flow === "device") {
          window.open(r.verification_uri, "_blank", "noopener,noreferrer");
        } else {
          window.open((r as any).auth_url, "_blank", "noopener,noreferrer");
        }
      })
      .catch((e: Error) => setErr(String(e.message ?? e)));
    // extras intentionally captured at the moment of "continue" — the
    // checklist is frozen once we kick off the OAuth flow, so don't
    // rerun this effect on later toggles.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, profile, started]);

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
      } catch {
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
        ) : showsScopePicker && !started ? (
          <div className="space-y-3">
            <div className="text-[11px] text-[#737373] leading-relaxed">
              {baseScopes.length > 0 ? (
                <>
                  defaults (<code className="text-[#171717]">{baseScopes.join(", ")}</code>) are
                  always requested.
                </>
              ) : (
                <>no scopes are requested by default.</>
              )}
            </div>
            <details className="border border-[#e5e5e5] rounded bg-[#fafafa] group">
              <summary className="cursor-pointer list-none flex items-center gap-2 px-2 py-1.5 text-[11px] text-[#171717] hover:bg-white rounded">
                <span className="inline-block w-3 text-[#a3a3a3] transition-transform group-open:rotate-90">
                  ›
                </span>
                <span>advanced permissions</span>
                <span className="ml-auto text-[10px] text-[#737373] tabular-nums">
                  {extras.size > 0 ? `${extras.size} selected` : "optional"}
                </span>
              </summary>
              <div className="max-h-[300px] overflow-y-auto p-2 space-y-3 border-t border-[#e5e5e5]">
                {optionalGroups.map((g) => (
                  <div key={g.title}>
                    <div className="text-[10px] uppercase tracking-[.1em] text-[#a3a3a3] mb-1">
                      {g.title}
                    </div>
                    <div className="grid grid-cols-1 gap-y-0.5">
                      {g.scopes.map((s) => {
                        const isBase = baseSet.has(s.id);
                        const checked = isBase || extras.has(s.id);
                        return (
                          <label
                            key={s.id}
                            className={
                              "flex items-center gap-2 text-[11px] py-0.5 px-1 rounded " +
                              (isBase
                                ? "text-[#a3a3a3]"
                                : "text-[#171717] cursor-pointer hover:bg-white")
                            }
                          >
                            <input
                              type="checkbox"
                              checked={checked}
                              disabled={isBase}
                              onChange={(e) => {
                                setExtras((prev) => {
                                  const next = new Set(prev);
                                  if (e.target.checked) next.add(s.id);
                                  else next.delete(s.id);
                                  return next;
                                });
                              }}
                              className="accent-[#171717]"
                            />
                            <code className="text-[11px]">{s.id}</code>
                            <span className="text-[#737373]">— {s.label}</span>
                            {isBase && (
                              <span className="ml-auto text-[10px] text-[#a3a3a3]">default</span>
                            )}
                          </label>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </details>
            {err && <div className="text-[11px] text-red-600 break-all">{err}</div>}
            <div className="flex gap-2 justify-end">
              <button
                type="button"
                onClick={onClose}
                className="text-[11px] px-3 py-1.5 border border-[#e5e5e5] text-[#737373] rounded hover:border-[#a3a3a3]"
              >
                cancel
              </button>
              <button
                type="button"
                onClick={() => setStarted(true)}
                className="text-[11px] px-3 py-1.5 bg-[#171717] text-white rounded"
              >
                continue ({baseScopes.length + extras.size} scopes)
              </button>
            </div>
          </div>
        ) : !start ? (
          <div className="text-[12px] text-[#737373]">opening browser…</div>
        ) : start.flow === "device" ? (
          <div className="space-y-3">
            <div className="text-[11px] text-[#737373] leading-relaxed">
              browser opened to <code className="text-[#171717]">{start.verification_uri}</code>.
              enter this code:
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
