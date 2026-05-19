import { useState } from "react";
import { logout, type Whoami } from "../lib/api";
import { AddDeviceModal } from "./AddDeviceModal";

// Global header — rendered above every route. Logo links home; the
// nav cluster on the right surfaces the logged-in identity and the
// dashboard's top-level actions (add device, analytics, settings,
// log out).
//
// Owns the add-device modal state so it's available anywhere; the
// rest of the app doesn't have to thread it through.
export function Header({ whoami }: { whoami: Whoami | null }) {
  const [showAddDevice, setShowAddDevice] = useState(false);
  return (
    <>
      <header className="">
        <div className="mx-auto w-full max-w-[1100px] px-4 sm:px-6 py-4 flex items-center gap-4">
          <a href="#/" aria-label="Home" className="shrink-0">
            <img src="/claw-patrol-logo.svg" alt="Claw Patrol" className="h-8 sm:h-10 w-auto" />
          </a>
          <nav className="ml-auto flex items-center gap-2">
            <Whoami whoami={whoami} />
            <button
              type="button"
              onClick={() => setShowAddDevice(true)}
              className="w-[36px] h-[36px] rounded-full border-1.5 border-navy text-navy flex items-center justify-center hover:bg-navy-100 transition-colors"
              title="add device"
              aria-label="Add device"
            >
              <Icon paths={["M12 5v14M5 12h14"]} />
            </button>
            <a
              href="#/analytics"
              className="w-[36px] h-[36px] rounded-full border-1.5 border-navy text-navy flex items-center justify-center hover:bg-navy-100 transition-colors"
              title="analytics"
              aria-label="Analytics"
            >
              <Icon paths={["M3 3v18h18", "m7 16 4-8 4 4 4-6"]} />
            </a>
            <a
              href="#/settings"
              className="w-[36px] h-[36px] rounded-full border-1.5 border-navy text-navy flex items-center justify-center hover:bg-navy-100 transition-colors"
              title="settings"
              aria-label="Settings"
            >
              <SettingsIcon />
            </a>
            <LogoutButton whoami={whoami} />
          </nav>
        </div>
      </header>
      {showAddDevice && (
        <AddDeviceModal publicURL={whoami?.public_url} onClose={() => setShowAddDevice(false)} />
      )}
    </>
  );
}

// Whoami renders the "<user> via <auth_method>" caption that tells
// the operator which credential the server thinks they're using.
// Empty user (no principal on the context) collapses to nothing
// rather than rendering a confusing "via ".
function Whoami({ whoami }: { whoami: Whoami | null }) {
  if (!whoami?.user) return null;
  const method =
    whoami.auth_method === "password"
      ? "password"
      : whoami.auth_method === "tailscale"
        ? "tailscale"
        : null;
  return (
    <span className="hidden sm:flex items-baseline gap-1 mr-2 text-sm text-text-muted">
      <span className="font-medium text-text">{whoami.user}</span>
      {method && (
        <>
          <span>via</span>
          <span>{method}</span>
        </>
      )}
    </span>
  );
}

// LogoutButton is enabled only when the active session is one the
// gateway can revoke — i.e. password auth. Tailnet allowlist hits
// have no server-side session to clear (the operator's tailnet
// identity is what's letting them in), so the button stays visible
// but disabled with a tooltip explaining why.
function LogoutButton({ whoami }: { whoami: Whoami | null }) {
  const method = whoami?.auth_method;
  const enabled = method === "password";
  const title = enabled
    ? "log out"
    : method === "tailscale"
      ? "tailnet auth — disconnect from tailscale to revoke access"
      : "log out";
  const handle = async () => {
    if (!enabled) return;
    try {
      await logout();
    } finally {
      // Even on a network error we reload — the cookie may have
      // been cleared client-side, in which case the gate will
      // redirect to /__login on the next request.
      window.location.href = "/__login";
    }
  };
  const base =
    "w-[36px] h-[36px] rounded-full border-1.5 border-navy flex items-center justify-center transition-colors";
  const enabledCls = "text-navy hover:bg-navy-100 cursor-pointer";
  const disabledCls = "text-text-subtle opacity-50 cursor-not-allowed";
  return (
    <button
      type="button"
      onClick={handle}
      disabled={!enabled}
      className={`${base} ${enabled ? enabledCls : disabledCls}`}
      title={title}
      aria-label={enabled ? "Log out" : "Log out (disabled — tailnet auth)"}
    >
      <LogoutIcon />
    </button>
  );
}

function Icon({ paths }: { paths: string[] }) {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {paths.map((d) => (
        <path key={d} d={d} />
      ))}
    </svg>
  );
}

function SettingsIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
  );
}

// LogoutIcon is the power-button glyph from dashboard/public/logout.svg
// (svgrepo, MIT). Inlined here for color/stroke control + to keep
// the asset count small. Using currentColor lets the parent button
// switch between active/disabled states without two SVGs.
function LogoutIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
      <path d="M14.625 4.109v1.568c3.265 1.103 5.625 4.193 5.625 7.823 0 4.547-3.7 8.25-8.25 8.25s-8.25-3.703-8.25-8.25c0-3.63 2.358-6.72 5.625-7.823V4.11C5.27 5.258 2.25 9.031 2.25 13.5c0 5.376 4.374 9.75 9.75 9.75s9.75-4.374 9.75-9.75c0-4.469-3.02-8.242-7.125-9.391Z" />
      <rect width="1.5" height="12.75" x="11.25" y="0.75" />
    </svg>
  );
}
