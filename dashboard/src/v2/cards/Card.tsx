import type { ReactNode } from "react";

type CardProps = {
  title: string;
  count?: number;
  // countAccent renders a butter-toned chip next to the count — used
  // when a subset of rows demands attention (e.g. pending approvals
  // mixed into the Actions table).
  countAccent?: string;
  action?: { label: string; onClick: () => void };
  children: ReactNode;
  tight?: boolean;
};

// Card primitive ported from unclaw's dashboard. Two-tone header
// (uppercase tracking + muted text), border-bordered body. v2 uses
// these everywhere a section needs a labeled box.
export function Card({ title, count, countAccent, action, children, tight }: CardProps) {
  return (
    <section className="mb-4 border border-canvas-dark bg-canvas-light">
      <header className="flex items-center justify-between border-b border-canvas-dark px-4 py-3 bg-canvas-muted">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-text-muted">
          {title}
          {typeof count === "number" && count > 0 && (
            <span className="ml-2 inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-canvas-dark px-1.5 text-[10px] font-medium text-text">
              {count}
            </span>
          )}
          {countAccent && (
            <span className="ml-2 inline-flex h-4 items-center rounded-full bg-butter-100 px-1.5 text-[10px] font-medium text-butter-900">
              {countAccent}
            </span>
          )}
        </h2>
        {action && (
          <button
            type="button"
            onClick={action.onClick}
            className="text-xs text-text-muted hover:text-text transition-colors"
          >
            {action.label} →
          </button>
        )}
      </header>
      <div className={tight ? "" : "px-4 py-4"}>{children}</div>
    </section>
  );
}
