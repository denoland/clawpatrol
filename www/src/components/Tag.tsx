import type { ReactNode } from "react";

export type Tone = "success" | "danger" | "warning" | "info" | "neutral";

const tones: Record<Tone, string> = {
  success: "bg-success-50 border-success-200 text-success-800",
  danger: "bg-danger-50 border-danger-200 text-danger-800",
  warning: "bg-butter-100 border-butter-200 text-butter-800",
  info: "bg-navy-50 border-navy-200 text-navy-800",
  neutral: "bg-canvas border-canvas-dark text-text-muted",
};

const base =
  "inline-block text-2xs uppercase tracking-[.05em] font-semibold " +
  "px-1.5 py-0.5 squircle-md border";

export function Tag({
  tone = "neutral",
  className,
  children,
  ...rest
}: {
  tone?: Tone;
  className?: string;
  children: ReactNode;
  title?: string;
}) {
  return (
    <span className={`${base} ${tones[tone]} ${className ?? ""}`} {...rest}>
      {children}
    </span>
  );
}
