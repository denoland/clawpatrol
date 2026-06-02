import type { ReactNode } from "react";
import type { Whoami } from "../lib/api";

// Global header — rendered above every route. Logo links home; the
// nav cluster on the right is four circular icon buttons for the
// dashboard's top-level sections (devices, analytics, settings,
// account). Identity + log-out moved to the account page.
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
  // Single-device pages are part of the Devices section, so the nav
  // button stays lit when drilling into a device.
  const devicesActive = currentRoute === "devices" || currentRoute === "device";
  return (
    <header className="border-b-1.5 border-b-canvas-muted">
      <div className="mx-auto w-full max-w-7xl px-4 sm:px-6 py-3 flex items-center gap-4">
        <a href="#/" aria-label="Home" className="shrink-0">
          <img
            src={import.meta.env.BASE_URL + "claw-patrol-logo.svg"}
            alt="Claw Patrol"
            className="h-8 w-auto hidden xs:block"
          />
          <img
            src={import.meta.env.BASE_URL + "claw-patrol-icon.svg"}
            alt="Claw Patrol"
            className="h-8 w-auto xs:hidden"
          />
        </a>
        <nav className="ml-auto flex items-center gap-1">
          <NavLink href="#/devices" label="Devices" active={devicesActive}>
            <DesktopNavIcon />
          </NavLink>
          <NavLink href="#/analytics" label="Analytics" active={currentRoute === "analytics"}>
            <Icon paths={["M3 3v18h18", "m7 16 4-8 4 4 4-6"]} />
          </NavLink>
          <NavLink href="#/settings" label="Settings" active={currentRoute === "settings"}>
            <SettingsIcon />
          </NavLink>
          <NavLink href="#/account" label="Account" active={currentRoute === "account"}>
            <AccountIcon />
          </NavLink>
        </nav>
      </div>
    </header>
  );
}

// NavLink couples the aria-label and the tooltip text so they can't
// drift apart. If a future link needs them to differ, split it back
// into two props (label + tooltip) rather than reaching into the
// className soup at the call site.
function NavLink({
  href,
  label,
  active,
  children,
}: {
  href: string;
  label: string;
  active: boolean;
  children: ReactNode;
}) {
  const NAV_BASE =
    "group relative w-9 h-9 squircle-md border-navy-100 text-navy flex items-center justify-center hover:bg-navy-100 transition-colors";
  const NAV_ACTIVE = "bg-navy-100";

  return (
    <a
      href={href}
      className={`${NAV_BASE} ${active ? NAV_ACTIVE : ""}`}
      aria-current={active ? "page" : undefined}
      aria-label={label}
    >
      {children}
      <NavTooltip>{label}</NavTooltip>
    </a>
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
        "max-w-[14rem] text-center leading-snug font-bold z-10 " +
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

// DesktopNavIcon is the computer-monitor glyph from Logos.tsx,
// re-stroked at the nav button's standard 18px size so it visually
// matches the other three icons.
function DesktopNavIcon() {
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
      <rect width="20" height="14" x="2" y="3" rx="2" />
      <line x1="8" x2="16" y1="21" y2="21" />
      <line x1="12" x2="12" y1="17" y2="21" />
    </svg>
  );
}
