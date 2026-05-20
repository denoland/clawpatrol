type Weight = "light" | "medium" | "dark" | "full";

type ShadeBarProps = {
  /** Coverage of the foreground pattern over the row. */
  weight?: Weight;
  /** Height utility (Tailwind class). */
  height?: string;
  /** Foreground (pattern color) Tailwind class — used as `currentColor`. */
  fg?: string;
  /** Background Tailwind class. Empty = transparent; whatever's behind
   *  shows through the pattern's transparent areas. */
  bg?: string;
  class?: string;
};

// Conic-gradient patterns that paint hard-edged square "pixels" — no
// font/glyph dependency, and unlike radial dots the edges are axis-
// aligned squares (conic transitions land on the cardinal directions
// from the tile center). Approximates the four Unicode block-shade
// chars: ░ ▒ ▓ █.
//
// Tile = 4×4px, divided into four 2×2px quadrants.
//   • light  → 1 of 4 quadrants filled (top-right)        → 25%
//   • medium → 2 of 4 quadrants filled (diagonal checker) → 50%
//   • dark   → 3 of 4 quadrants filled (only top-left empty) → 75%
//   • full   → solid background-color                     → 100%
const STYLE: Record<Weight, Record<string, string>> = {
  light: {
    backgroundImage: "conic-gradient(currentColor 25%, transparent 0)",
    backgroundSize: "4px 4px",
  },
  medium: {
    backgroundImage:
      "conic-gradient(currentColor 25%, transparent 0 50%, currentColor 0 75%, transparent 0)",
    backgroundSize: "4px 4px",
  },
  dark: {
    backgroundImage: "conic-gradient(currentColor 75%, transparent 0)",
    backgroundSize: "4px 4px",
  },
  full: { backgroundColor: "currentColor" },
};

export function ShadeBar({
  weight = "medium",
  height = "h-4",
  fg = "text-canvas-400",
  bg = "",
  class: cls = "",
}: ShadeBarProps) {
  return (
    <div
      aria-hidden="true"
      class={`w-full ${fg} ${bg} ${height} ${cls}`}
      style={STYLE[weight]}
    />
  );
}

type ShadeGradientProps = {
  /** Foreground (pattern color) Tailwind class — passed to each ShadeBar's `fg`. */
  color?: string;
  /** Background Tailwind class — passed to each ShadeBar's `bg`. */
  background?: string;
  /** Reverse the stack so it goes dark → light (top to bottom). Default
   *  is light → dark, which reads as "fading into solid" — useful
   *  above a dark section. Invert reads as "fading out of solid" —
   *  useful below a dark section. */
  invert?: boolean;
  /** Per-row height (Tailwind class) applied to every ShadeBar. */
  rowHeight?: string;
  class?: string;
};

// Stack of all four ShadeBar weights, ordered light → dark by default
// (or reversed when `invert` is set). Useful as a section divider with
// a terminal-shade gradient feel.
export function ShadeGradient({
  color,
  background,
  invert = false,
  rowHeight,
  class: cls = "",
}: ShadeGradientProps) {
  const order: Weight[] = invert
    ? ["full", "dark", "medium", "light"]
    : ["light", "medium", "dark", "full"];
  return (
    <div aria-hidden="true" class={cls}>
      {order.map((w) => (
        <ShadeBar
          key={w}
          weight={w}
          fg={color}
          bg={background}
          height={rowHeight}
        />
      ))}
    </div>
  );
}
