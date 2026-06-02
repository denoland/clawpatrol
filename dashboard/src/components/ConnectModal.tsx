import { useEffect, useRef, useState } from "react";
import {
  oauthDevicePoll,
  oauthExchange,
  oauthStart,
  type OAuthIntegrationUI,
  type OAuthStartResp,
} from "../lib/api";
import { Button } from "./Button";
import { Modal } from "./Modal";

export function ConnectModal({
  id,
  oauth,
  onClose,
  onDone,
}: {
  id: string;
  oauth?: OAuthIntegrationUI | null;
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
    oauthStart(id, extraList)
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
  }, [id, started]);

  // Stable ref to onDone — parent re-renders (App refreshes integrations
  // every 3s) reset the lambda otherwise, killing the polling interval
  // before its 5s tick can fire.
  const onDoneRef = useRef(onDone);
  onDoneRef.current = onDone;

  // Auto-complete path: when the OAuth callback page in another tab
  // POSTs /api/oauth/exchange successfully, it pings the BroadcastChannel
  // so this modal can close itself instead of asking the user to copy
  // the code into the input field below. Lazy `try` so older browsers
  // without BroadcastChannel just fall back to the copy-paste UX.
  useEffect(() => {
    if (!start || start.flow === "device" || done) return;
    let ch: BroadcastChannel | null = null;
    try {
      ch = new BroadcastChannel("oauth");
      ch.onmessage = (e) => {
        if (e.data?.type === "connected" && e.data?.state === start.state) {
          setDone(true);
          setTimeout(() => onDoneRef.current(), 800);
        }
      };
    } catch {
      /* no BroadcastChannel — copy-paste fallback still works */
    }
    return () => {
      try {
        ch?.close();
      } catch {
        /* no-op */
      }
    };
  }, [start, done]);

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
    <Modal title={`Connect ${id}`} onClose={onClose}>
      <div className="p-5">
        {done ? (
          <div className="py-6 text-center">
            <div className="text-2xl mb-2">✓</div>
            <div className="text-xs text-text">connected</div>
          </div>
        ) : showsScopePicker && !started ? (
          <div className="space-y-3">
            <div className="text-xs text-text-muted leading-relaxed">
              {baseScopes.length > 0 ? (
                <>
                  defaults (<code className="text-text">{baseScopes.join(", ")}</code>) are always
                  requested.
                </>
              ) : (
                <>no scopes are requested by default.</>
              )}
            </div>
            <details className="border border-canvas-300 rounded bg-canvas-muted group">
              <summary className="cursor-pointer list-none flex items-center gap-2 px-2 py-1.5 text-xs text-text hover:bg-canvas rounded">
                <span className="inline-block w-3 text-text-subtle transition-transform group-open:rotate-90">
                  ›
                </span>
                <span>advanced permissions</span>
                <span className="ml-auto text-2xs text-text-muted tabular-nums">
                  {extras.size > 0 ? `${extras.size} selected` : "optional"}
                </span>
              </summary>
              <div className="max-h-75 overflow-y-auto p-2 space-y-3 border-t border-canvas-300">
                {optionalGroups.map((g) => (
                  <div key={g.title}>
                    <div className="font-mono text-2xs uppercase tracking-wider text-text-subtle mb-1">
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
                              "flex items-center gap-2 text-xs py-0.5 px-1 rounded " +
                              (isBase
                                ? "text-text-subtle"
                                : "text-text cursor-pointer hover:bg-canvas")
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
                              className="accent-text"
                            />
                            <code className="text-xs">{s.id}</code>
                            <span className="text-text-muted">— {s.label}</span>
                            {isBase && (
                              <span className="ml-auto text-2xs text-text-subtle">default</span>
                            )}
                          </label>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </details>
            {err && <div className="text-xs text-rust-700 break-all">{err}</div>}
            <div className="flex gap-2 justify-end">
              <Button variant="outline" onClick={onClose}>
                cancel
              </Button>
              <Button onClick={() => setStarted(true)}>
                continue ({baseScopes.length + extras.size} scopes)
              </Button>
            </div>
          </div>
        ) : !start ? (
          <div className="text-xs text-text-muted">opening browser…</div>
        ) : start.flow === "device" ? (
          <div className="space-y-3">
            <div className="text-xs text-text-muted leading-relaxed">
              browser opened to <code className="text-text">{start.verification_uri}</code>. enter
              this code:
            </div>
            <div className="font-mono text-3xl tracking-[.18em] text-text text-center py-3 bg-canvas-muted border border-canvas-300 rounded select-all">
              {start.user_code}
            </div>
            <div className="text-xs text-text-subtle text-center">waiting for approval…</div>
            {err && <div className="text-xs text-rust-700 break-all">{err}</div>}
            <div className="flex justify-end">
              <Button variant="outline" onClick={onClose}>
                cancel
              </Button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="text-sm text-text-muted font-sans leading-relaxed">
              Browser opened. Log in, then paste the code from the redirect URL bar (after{" "}
              <code className="text-text">?code=</code>) here:
            </div>
            <form onSubmit={submit}>
              <input
                type="text"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="paste code here"
                className="w-full text-xs border border-canvas-dark rounded px-2 py-2 focus:outline-none focus:border-text font-mono transition-colors"
                autoFocus
              />
              {err && <div className="text-xs text-rust-700 mt-2 break-all">{err}</div>}
              <div className="flex gap-2 mt-8 justify-end">
                <Button variant="outline" onClick={onClose}>
                  cancel
                </Button>
                <Button type="submit" disabled={busy || !code}>
                  {busy ? "exchanging…" : "connect"}
                </Button>
              </div>
            </form>
          </div>
        )}
      </div>
    </Modal>
  );
}
