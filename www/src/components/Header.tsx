import { useState } from "react";
import type { Whoami } from "../lib/api";
import { AddDeviceModal } from "./AddDeviceModal";

// Global header — rendered above every route. Logo links home; three
// icon buttons cover the dashboard's top-level actions: add a device
// (opens AddDeviceModal), jump to analytics, jump to settings.
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
            <button
              type="button"
              onClick={() => setShowAddDevice(true)}
              className="w-[36px] h-[36px] rounded-full border-2 border-navy text-navy flex items-center justify-center hover:bg-navy-100 transition-colors"
              title="add device"
              aria-label="Add device"
            >
              <Icon paths={["M12 5v14M5 12h14"]} />
            </button>
            <a
              href="#/analytics"
              className="w-[36px] h-[36px] rounded-full border-2 border-navy text-navy flex items-center justify-center hover:bg-navy-100 transition-colors"
              title="analytics"
              aria-label="Analytics"
            >
              <Icon paths={["M3 3v18h18", "m7 16 4-8 4 4 4-6"]} />
            </a>
            <a
              href="#/settings"
              className="w-[36px] h-[36px] rounded-full border-2 border-navy text-navy flex items-center justify-center hover:bg-navy-100 transition-colors"
              title="settings"
              aria-label="Settings"
            >
              <SettingsIcon />
            </a>
          </nav>
        </div>
      </header>
      {showAddDevice && (
        <AddDeviceModal publicURL={whoami?.public_url} onClose={() => setShowAddDevice(false)} />
      )}
    </>
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
