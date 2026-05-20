type DotFieldProps = {
  /** Height utility (Tailwind class). */
  height?: string;
  /** Extra classes — applied after defaults so callers can override
   *  width, color, margins, positioning, etc. */
  class?: string;
};

// A faint terminal-style dot fill — square 8×8px grid, one pixel dot
// per cell. Decorative only; hidden from assistive tech.
export function DotField({ height = "h-6", class: cls = "" }: DotFieldProps) {
  return (
    <div
      aria-hidden="true"
      class={`w-full text-canvas-400 ${height} ${cls}`}
      style={{
        backgroundImage:
          "radial-gradient(circle, currentColor 0.5px, transparent 1px)",
        backgroundSize: "4px 4px",
        backgroundPosition: "-1px -1px",
      }}
    />
  );
}
