import type { ReactNode } from "react";
import type { Whoami } from "../lib/api";

// Global header — rendered above every route. Logo links home; the
// nav cluster on the right is four circular icon buttons for the
// dashboard's top-level sections (profiles, analytics, settings,
// account). Identity + log-out live on the account page.
//
// `whoami` is still accepted (currently unused) so consumers don't
// need to thread route-specific data through; future header
// affordances (e.g. an unread indicator on the account button) can
// read it without a signature change.
export function Header({
  whoami: _whoami,
  currentRoute,
}: {
  whoami: Whoami | null;
  currentRoute?: string;
}) {
  const navBase =
    "group relative w-[36px] h-[36px] rounded-full border-1.5 border-navy text-navy flex items-center justify-center bg-canvas hover:bg-canvas-muted transition-colors";
  const navActive = "bg-navy-100";
  // The Profiles section owns the per-profile drill-in and the
  // legacy per-device page (which is reached from a profile's flow
  // map) — keep the nav button lit on either drill-in route so the
  // operator can see where they are.
  const profilesActive =
    currentRoute === "profiles" || currentRoute === "profile_detail" || currentRoute === "device";
  const analyticsActive = currentRoute === "analytics";
  const settingsActive = currentRoute === "settings";
  const accountActive = currentRoute === "account";
  return (
    <header className="bg-transparent">
      <div className="mx-auto w-full max-w-[1100px] px-4 sm:px-6 py-4 flex items-center gap-4">
        <a href="#/" aria-label="Home" className="shrink-0">
          <img
            src={import.meta.env.BASE_URL + "claw-patrol-logo.svg"}
            alt="Claw Patrol"
            className="h-6 sm:h-8 w-auto"
          />
        </a>
        <nav className="ml-auto flex items-center gap-2">
          <a
            href="#/profiles"
            className={`${navBase} ${profilesActive ? navActive : ""}`}
            aria-current={profilesActive ? "page" : undefined}
            aria-label="Profiles"
          >
            <ProfilesNavIcon />
            <NavTooltip>Profiles</NavTooltip>
          </a>
          <a
            href="#/analytics"
            className={`${navBase} ${analyticsActive ? navActive : ""}`}
            aria-current={analyticsActive ? "page" : undefined}
            aria-label="Analytics"
          >
            <Icon paths={["M3 3v18h18", "m7 16 4-8 4 4 4-6"]} />
            <NavTooltip>Analytics</NavTooltip>
          </a>
          <a
            href="#/settings"
            className={`${navBase} ${settingsActive ? navActive : ""}`}
            aria-current={settingsActive ? "page" : undefined}
            aria-label="Settings"
          >
            <SettingsIcon />
            <NavTooltip>Settings</NavTooltip>
          </a>
          <a
            href="#/account"
            className={`${navBase} ${accountActive ? navActive : ""}`}
            aria-current={accountActive ? "page" : undefined}
            aria-label="Account"
          >
            <AccountIcon />
            <NavTooltip>Account</NavTooltip>
          </a>
        </nav>
      </div>
    </header>
  );
}

// NavTooltip is the custom hover/focus label for header nav buttons.
// Positioned absolutely below the parent (which must be `relative
// group`); fades in on hover or keyboard focus. `pointer-events-none`
// so the tooltip itself never steals the hover.
function NavTooltip({ children }: { children: ReactNode }) {
  return (
    <span
      role="tooltip"
      className={
        "pointer-events-none absolute top-full left-1/2 -translate-x-1/2 mt-1.5 " +
        "px-2 py-1 bg-navy text-canvas text-2xs font-mono uppercase tracking-wider " +
        "max-w-[220px] text-center leading-snug font-bold z-10 " +
        "opacity-0 group-hover:opacity-100 group-focus-visible:opacity-100 " +
        "transition-opacity duration-100"
      }
    >
      {children}
    </span>
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
      aria-hidden="true"
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
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
  );
}

// AccountIcon is a stroked head-and-shoulders glyph matching the
// outline style of the Analytics chart and Settings cog icons.
function AccountIcon() {
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
      aria-hidden="true"
    >
      <circle cx="12" cy="8" r="4" />
      <path d="M4 21v-1a8 8 0 0 1 16 0v1" />
    </svg>
  );
}

// ProfilesNavIcon is a 3-card stack glyph — visually distinct from
// the account ProfileIcon (head-and-shoulders) so the two nav
// buttons aren't confused with each other. Stroked to match the
// outline style of the other nav icons.
function ProfilesNavIcon() {
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
      aria-hidden="true"
    >
      <rect width="16" height="6" x="4" y="4" rx="1" />
      <rect width="16" height="6" x="4" y="14" rx="1" />
      <line x1="8" x2="14" y1="7" y2="7" />
      <line x1="8" x2="14" y1="17" y2="17" />
    </svg>
  );
}
