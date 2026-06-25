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

type DeviceStart = Extract<OAuthStartResp, { flow: "device" }>;
type AuthCodeStart = Exclude<OAuthStartResp, { flow: "device" }>;

type ConnectState =
  | { kind: "scopePicker" }
  | { kind: "idle" }
  | { kind: "starting" }
  | { kind: "startError"; message: string; extraScopes?: string[] }
  | { kind: "device"; start: DeviceStart; browserOpened: boolean; error?: string }
  | { kind: "authCode"; start: AuthCodeStart; browserOpened: boolean; error?: string }
  | { kind: "done" };

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
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  // The picker only appears when the plugin declared optional scopes.
  const optionalGroups = oauth?.optional_scopes ?? [];
  const baseScopes = oauth?.base_scopes ?? [];
  const showsScopePicker = optionalGroups.length > 0;
  const [state, setState] = useState<ConnectState>(() =>
    showsScopePicker ? { kind: "scopePicker" } : { kind: "idle" },
  );
  const [extras, setExtras] = useState<Set<string>>(() => new Set());
  const baseSet = new Set(baseScopes);

  async function startOAuth(extraScopes?: string[]) {
    // Open synchronously while still inside the click gesture so popup
    // blockers treat the OAuth tab as user-initiated. Navigate it after
    // oauthStart returns; if the start call fails, close the parked tab.
    const popup = window.open("about:blank", "_blank");
    if (popup) {
      popup.opener = null;
    }
    setState({ kind: "starting" });
    try {
      const start = await oauthStart(id, extraScopes);
      const url = start.flow === "device" ? start.verification_uri : start.auth_url;
      if (popup) {
        popup.location.href = url;
      }
      if (start.flow === "device") {
        setState({ kind: "device", start, browserOpened: popup !== null });
      } else {
        setState({ kind: "authCode", start, browserOpened: popup !== null });
      }
    } catch (e: any) {
      try {
        popup?.close();
      } catch {
        /* ignore */
      }
      setState({ kind: "startError", message: String(e.message ?? e), extraScopes });
    }
  }

  // Stable ref to onDone — parent re-renders (App refreshes integrations
  // every 3s) reset the lambda otherwise, killing the polling interval
  // before its 5s tick can fire.
  const onDoneRef = useRef(onDone);
  onDoneRef.current = onDone;

  const authCodeStart = state.kind === "authCode" ? state.start : null;

  // Auto-complete path: when the OAuth callback page in another tab
  // POSTs /api/oauth/exchange successfully, it pings the BroadcastChannel
  // so this modal can close itself instead of asking the user to copy
  // the code into the input field below. Lazy `try` so older browsers
  // without BroadcastChannel just fall back to the copy-paste UX.
  useEffect(() => {
    if (!authCodeStart) return;
    let ch: BroadcastChannel | null = null;
    try {
      ch = new BroadcastChannel("oauth");
      ch.onmessage = (e) => {
        if (e.data?.type === "connected" && e.data?.state === authCodeStart.state) {
          setState({ kind: "done" });
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
  }, [authCodeStart]);

  const deviceStart = state.kind === "device" ? state.start : null;

  useEffect(() => {
    if (!deviceStart) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    let intervalSec = deviceStart.interval || 5;
    // RFC 8628: client must respect the `interval` field returned on
    // slow_down. Reschedule via setTimeout instead of fixed interval
    // so each tick uses the latest cadence GitHub asked for.
    const tick = async () => {
      if (cancelled) return;
      try {
        const r = await oauthDevicePoll(deviceStart.state);
        if (cancelled) return;
        if (r.connected) {
          setState({ kind: "done" });
          setTimeout(() => onDoneRef.current(), 800);
          return;
        }
        if (r.interval && r.interval > intervalSec) {
          intervalSec = r.interval;
        }
        if (r.error && r.error !== "authorization_pending" && r.error !== "slow_down") {
          setState((current) =>
            current.kind === "device" && current.start.state === deviceStart.state
              ? { ...current, error: `${r.error}: ${r.detail || ""}` }
              : current,
          );
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
  }, [deviceStart]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (state.kind !== "authCode") return;
    const start = state.start;
    setBusy(true);
    setState({ kind: "authCode", start, browserOpened: state.browserOpened });
    try {
      await oauthExchange(start.state, code);
      setState({ kind: "done" });
      setTimeout(onDone, 800);
    } catch (e: any) {
      setState({
        kind: "authCode",
        start,
        browserOpened: state.browserOpened,
        error: String(e.message ?? e),
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={`Connect ${id}`} onClose={onClose}>
      <div className="p-5">
        {state.kind === "done" ? (
          <div className="py-6 text-center">
            <div className="text-2xl mb-2">✓</div>
            <div className="text-xs text-text">connected</div>
          </div>
        ) : state.kind === "scopePicker" ? (
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
            <div className="flex gap-2 justify-end">
              <Button variant="outline" onClick={onClose}>
                cancel
              </Button>
              <Button onClick={() => startOAuth(Array.from(extras))}>
                continue ({baseScopes.length + extras.size} scopes)
              </Button>
            </div>
          </div>
        ) : state.kind === "idle" ? (
          <div className="space-y-3">
            <div className="text-xs text-text-muted leading-relaxed">
              Open your browser to complete the OAuth connection.
            </div>
            <div className="flex gap-2 justify-end">
              <Button variant="outline" onClick={onClose}>
                cancel
              </Button>
              <Button onClick={() => startOAuth()}>connect</Button>
            </div>
          </div>
        ) : state.kind === "starting" ? (
          <div className="text-xs text-text-muted">opening browser…</div>
        ) : state.kind === "startError" ? (
          <div className="space-y-3">
            <div className="text-xs text-text-muted">Could not open the browser.</div>
            <div className="text-xs text-rust-700 break-all">{state.message}</div>
            <div className="flex gap-2 justify-end">
              <Button variant="outline" onClick={onClose}>
                cancel
              </Button>
              <Button onClick={() => startOAuth(state.extraScopes)}>try again</Button>
            </div>
          </div>
        ) : state.kind === "device" ? (
          <div className="space-y-3">
            <div className="text-xs text-text-muted leading-relaxed">
              {state.browserOpened ? "browser opened to " : "Open "}
              <a
                href={state.start.verification_uri}
                target="_blank"
                rel="noreferrer"
                className="underline text-text"
              >
                {state.start.verification_uri}
              </a>
              . enter this code:
            </div>
            <div className="font-mono text-3xl tracking-[.18em] text-text text-center py-3 bg-canvas-muted border border-canvas-300 rounded select-all">
              {state.start.user_code}
            </div>
            <div className="text-xs text-text-subtle text-center">waiting for approval…</div>
            {state.error && <div className="text-xs text-rust-700 break-all">{state.error}</div>}
            <div className="flex justify-end">
              <Button variant="outline" onClick={onClose}>
                cancel
              </Button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="text-sm text-text-muted font-sans leading-relaxed">
              {state.browserOpened ? (
                <>Browser opened.</>
              ) : (
                <>
                  Browser popup was blocked. Open{" "}
                  <a
                    href={state.start.auth_url}
                    target="_blank"
                    rel="noreferrer"
                    className="underline text-text"
                  >
                    the OAuth URL
                  </a>
                  .
                </>
              )}{" "}
              Log in, then paste the code from the redirect URL bar (after{" "}
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
              {state.error && (
                <div className="text-xs text-rust-700 mt-2 break-all">{state.error}</div>
              )}
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
