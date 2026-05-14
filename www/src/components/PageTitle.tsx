import type { ReactNode } from "react";

// PageTitle renders a consistent breadcrumb + optional contextual
// actions strip below the global Header on inner routes. The home
// page doesn't render this; every other route does.
//
// `trail` is the list of breadcrumb segments. The last one is the
// current page (rendered without a link); the rest get rendered as
// links if `href` is provided, plain text otherwise.
//
// `actions` are page-specific affordances (filter chip, profile
// picker, delete button, etc.) that live on the same row as the
// breadcrumb, right-aligned.
export type Crumb = {
  label: ReactNode;
  href?: string;
};

export function PageTitle({ trail, actions }: { trail: Crumb[]; actions?: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 flex-wrap">
      <nav aria-label="Breadcrumb" className="flex items-baseline gap-1.5 text-sm">
        {trail.map((c, i) => {
          const isLast = i === trail.length - 1;
          return (
            <span key={i} className="flex items-baseline gap-1.5">
              {c.href && !isLast ? (
                <a href={c.href} className="text-text-subtle hover:text-text">
                  {c.label}
                </a>
              ) : (
                <span className={isLast ? "text-text-muted" : "text-text-subtle"}>{c.label}</span>
              )}
              {!isLast && <span className="text-text-subtle">/</span>}
            </span>
          );
        })}
      </nav>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}
