import type { ReactNode } from "react";

export function PageHeader({
  title,
  subhead,
  children,
}: {
  title: string;
  subhead?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="mb-6 flex items-start justify-between gap-3">
      <div className="min-w-0 flex-1">
        <h1 className="text-balance text-xl font-semibold text-text md:text-2xl">{title}</h1>
        {subhead && <p className="mt-1 text-balance text-sm text-text-muted">{subhead}</p>}
      </div>
      {children && <div className="flex items-center gap-2">{children}</div>}
    </div>
  );
}
