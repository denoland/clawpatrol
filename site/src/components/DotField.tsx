type DotFieldProps = {
  /** Height utility (Tailwind class). */
  height?: string;
};

// A faint terminal-style dot fill — square 8×8px grid, one pixel dot
// per cell, painted in `text-neutral-400`. Decorative only; hidden
// from assistive tech.
export function DotField({ height = "h-8" }: DotFieldProps) {
  return (
    <div
      aria-hidden="true"
      class={`w-full text-neutral-400 ${height}`}
      style={{
        backgroundImage:
          "radial-gradient(circle, currentColor 0.5px, transparent 1px)",
        backgroundSize: "6px 6px",
      }}
    />
  );
}
