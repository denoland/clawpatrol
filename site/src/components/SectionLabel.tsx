export function SectionLabel({ children }: { children: string }) {
  return (
    <div class="text-center mb-16">
      <h2
        class="uppercase flex items-center gap-4 mx-auto w-max
          font-normal
           text-rust font-mono"
      >
        <Stripes />
        {children}
        <Stripes flip />
      </h2>
    </div>
  );
}

// Slashed stripes that ramp in thickness and density toward the text.
// Bottom-edge position follows c_i = (BAR_W - WIDTH_MAX) * (1 - (1 - t)^k),
// the same concave easing as HatchDivider, so stripes pile up at the
// trailing edge. Width grows linearly with i.
//
// VIEW_W is BAR_W + SLANT so the slanted top edge (which extends SLANT
// units to the right of the bottom edge) stays inside the viewBox —
// without this, the rightmost stripes' tops get clipped.
//
// The right-side group uses `rotate(180deg)` rather than scaleX(-1)
// so the slash direction is preserved (both sides slant the same way,
// like `////`). A horizontal mirror would have made the right side
// read as backslashes.
const STRIPE_COUNT = 13;
const BAR_W = 56;
const SLANT = 2;
const VIEW_W = BAR_W + SLANT;
const VIEW_H = 16;
const WIDTH_MIN = 0.5;
const WIDTH_MAX = 2;
const CURVE = 1.1;

const SHAPES = Array.from({ length: STRIPE_COUNT }, (_, i) => {
  const t = i / (STRIPE_COUNT - 1);
  const x = (BAR_W - WIDTH_MAX) * (1 - Math.pow(1 - t, CURVE));
  const w = WIDTH_MIN + (WIDTH_MAX - WIDTH_MIN) * t;
  return { x, w };
});

const Stripes = ({ flip = false }: { flip?: boolean }) => (
  <svg
    width={VIEW_W}
    height={VIEW_H}
    viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
    class="text-rust"
    aria-hidden="true"
    style={
      flip
        ? { transform: "rotate(180deg)", transformOrigin: "center" }
        : undefined
    }
  >
    {SHAPES.map(({ x, w }, i) => (
      <path
        key={i}
        d={`M ${x + SLANT} 0 L ${x + SLANT + w} 0 L ${x + w} ${VIEW_H} L ${x} ${VIEW_H} Z`}
        fill="currentColor"
      />
    ))}
  </svg>
);
