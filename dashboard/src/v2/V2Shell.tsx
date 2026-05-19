import type { ReactNode } from "react";
import type { V2Page } from "./V2App";

type Tab = {
  key: V2Page;
  label: string;
  href: string;
  badge?: number;
  badgeKind?: "neutral" | "warn";
};

// V2 dashboard shell — top-of-page header, sticky tab strip below.
// Layout mirrors unclaw's Shell.tsx (denoland/unclaw refinery/rig/
// dashboard/src/components/Shell.tsx) so a side-by-side comparison
// reads cleanly. Palette stays in clawpatrol's canvas/navy/rust
// tokens so v2 still feels part of this app.
export function V2Shell({
  current,
  hitlCount,
  children,
}: {
  current: V2Page;
  hitlCount: number;
  children: ReactNode;
}) {
  const tabs: Tab[] = [
    { key: "overview", label: "Overview", href: "#/v2" },
    {
      key: "actions",
      label: "Actions",
      href: "#/v2/actions",
      badge: hitlCount,
      badgeKind: "warn",
    },
    { key: "rules", label: "Rules", href: "#/v2/rules" },
    { key: "analytics", label: "Analytics", href: "#/v2/analytics" },
    { key: "profiles", label: "Profiles", href: "#/v2/profiles" },
    { key: "devices", label: "Devices", href: "#/v2/devices" },
    { key: "settings", label: "Settings", href: "#/v2/settings" },
  ];

  return (
    <div className="min-h-screen bg-canvas text-text antialiased">
      <header className="md:sticky md:top-0 md:z-30 bg-canvas-light/95 backdrop-blur">
        <div className="px-4 lg:px-6 flex flex-wrap items-center justify-between py-4">
          <a href="#/v2" aria-label="clawpatrol v2" className="inline-flex items-center gap-2">
            <img src="/claw-patrol-logo.svg" alt="Claw Patrol" className="h-6 w-auto" />
            <span className="text-xs uppercase tracking-widest text-text-muted border border-canvas-dark px-1.5 py-0.5">
              v2
            </span>
          </a>
          <div className="flex items-center gap-4 text-sm text-text-muted">
            <a href="#/" className="hover:text-text transition-colors underline decoration-dotted">
              switch to v1
            </a>
          </div>
        </div>
        <nav className="mx-auto flex gap-0 flex-wrap items-stretch relative">
          <div className="min-w-0 flex flex-wrap flex-col w-full md:flex-row items-stretch relative top-px">
            {tabs.map((tab) => {
              const active = current === tab.key;
              return (
                <a
                  key={tab.key}
                  href={tab.href}
                  className={`inline-flex w-full md:w-auto items-center gap-1.5 border-canvas-dark border-t md:border-l md:border-b last:md:border-r px-4 lg:px-6 py-2 lg:py-2.5 text-sm font-medium transition-colors duration-100 hover:bg-canvas-muted ${
                    active
                      ? "bg-canvas text-text md:border-b-transparent"
                      : "bg-canvas-light text-text-muted hover:text-text"
                  }`}
                >
                  <span>{tab.label}</span>
                  {tab.badge !== undefined && tab.badge > 0 && (
                    <Badge n={tab.badge} kind={tab.badgeKind ?? "neutral"} />
                  )}
                </a>
              );
            })}
            <div className="border-canvas-dark border-b border-l flex-auto"></div>
          </div>
        </nav>
      </header>
      <main className="px-6 py-8 pb-16">{children}</main>
    </div>
  );
}

function Badge({ n, kind }: { n: number; kind: "neutral" | "warn" }) {
  const base =
    "inline-flex items-center justify-center rounded-full text-[10px] font-semibold leading-none px-1.5 min-w-[1.125rem] h-[1.125rem]";
  const palette = kind === "warn" ? "bg-danger-100 text-danger-700" : "bg-canvas-dark text-text";
  return <span className={`${base} ${palette}`}>{n > 99 ? "99+" : n}</span>;
}
