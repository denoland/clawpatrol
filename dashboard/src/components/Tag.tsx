import type { ReactNode } from "react";

export type Tone = "success" | "danger" | "warning" | "info" | "neutral";

const tones: Record<Tone, string> = {
  success: "bg-success-100 border-success-200 text-success-800",
  danger: "bg-danger-50 border-danger-200 text-danger-800",
  warning: "bg-butter-200 border-butter-400 text-butter-800",
  info: "bg-navy-50 border-navy-200 text-navy-800",
  neutral: "bg-canvas-muted border-canvas-dark text-text-muted",
};

const base =
  "font-mono inline-flex items-center gap-1 text-2xs uppercase tracking-wider font-semibold " +
  "px-1.5 py-0.5 squircle-md border";

// Tag renders as a <span> by default; pass `onClick` to render as a
// <button> instead (e.g. for active-filter chips that dismiss on
// click). Pass `dismissible` to append a × glyph after the label.
export function Tag({
  tone = "neutral",
  className,
  onClick,
  dismissible,
  children,
  ...rest
}: {
  tone?: Tone;
  className?: string;
  onClick?: () => void;
  dismissible?: boolean;
  children: ReactNode;
  title?: string;
}) {
  const cls =
    `${base} ${tones[tone]} ` +
    (onClick ? "cursor-pointer hover:opacity-80 transition-opacity " : "") +
    (className ?? "");
  const body = (
    <>
      {children}
      {dismissible && (
        <span aria-hidden="true" className="text-2xs">
          ✕
        </span>
      )}
    </>
  );
  if (onClick) {
    return (
      <button type="button" onClick={onClick} className={cls} {...rest}>
        {body}
      </button>
    );
  }
  return (
    <span className={cls} {...rest}>
      {body}
    </span>
  );
}
