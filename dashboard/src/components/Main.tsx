import type { ReactNode } from "react";

// Page <main> wrapper. Owns the canonical max-width + horizontal
// gutter so every routed page lines up with the header content,
// and the standard vertical rhythm so pages don't drift.
//
// `centered` swaps the default vertical stack for a flex column
// that lets a single child sit centered in the remaining viewport
// (see OnboardPage).
export function Main({ children, centered }: { children: ReactNode; centered?: boolean }) {
  const base = "flex-1 mx-auto w-full max-w-7xl px-4 sm:px-6 py-6 pb-16";
  return <main className={`${base} ${centered ? "flex flex-col" : "space-y-4"}`}>{children}</main>;
}
