import type { ReactNode } from "react";

// PageTitle renders the page hero: a display-font heading for the
// current page (the last crumb in `trail`), an optional breadcrumb
// row below for any ancestor crumbs, and a right-aligned `actions`
// slot for page-specific affordances (filter chips, profile pickers,
// delete buttons, etc.).
//
// `trail` is the navigation path. The last item becomes the heading;
// the rest render as breadcrumb links above the home logo. The
// global Header already provides the "back to home" affordance, so
// there is no synthetic root crumb — callers pass only the page's
// own path.
export type Crumb = {
  label: ReactNode;
  href?: string;
};

export function PageTitle({ trail, actions }: { trail: Crumb[]; actions?: ReactNode }) {
  if (trail.length === 0) return null;
  const heading = trail[trail.length - 1];
  const crumbs = trail.slice(0, -1);
  return (
    <div className="flex flex-col gap-2 mb-6">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <h1 className="font-display text-2xl sm:text-3xl text-text leading-none">
          {heading.label}
        </h1>
        {actions && <div className="flex items-center gap-2">{actions}</div>}
      </div>
      {crumbs.length > 0 && (
        <nav aria-label="Breadcrumb" className="flex items-baseline gap-1.5 text-sm">
          {crumbs.map((c, i) => {
            const isLast = i === crumbs.length - 1;
            return (
              <span key={i} className="flex items-baseline gap-1.5">
                {c.href ? (
                  <a
                    href={c.href}
                    className="text-text-muted underline underline-offset-2 hover:text-text"
                  >
                    {c.label}
                  </a>
                ) : (
                  <span className="text-text-muted">{c.label}</span>
                )}
                {!isLast && <span className="text-text-muted">/</span>}
              </span>
            );
          })}
        </nav>
      )}
    </div>
  );
}
