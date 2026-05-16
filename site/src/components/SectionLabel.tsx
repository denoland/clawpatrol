export function SectionLabel({ children }: { children: string }) {
  return (
    <div class="text-center mb-16">
      <h2
        class="text-xl uppercase flex items-center gap-2 mx-auto w-max
          font-bold
           text-rust font-sans"
      >
        <Stripes />
        {children}
        <Stripes />
      </h2>
    </div>
  );
}

// Six skewed slashes rendered as explicit SVG parallelograms so every
// stripe has identical width. The previous repeating-linear-gradient
// + skewX combo clipped the edge stripes thinner than the middle ones
// because the gradient was painted into a rectangular bitmap before
// the skew, and the slanted edges of the resulting parallelogram
// trimmed those stripes at subpixel boundaries.
const Stripes = () => (
  <svg
    width="48"
    height="16"
    viewBox="0 0 48 16"
    class="text-rust"
    aria-hidden="true"
  >
    {[0, 8, 16, 24, 32, 40].map((x) => (
      <path
        key={x}
        d={`M ${x + 4} 0 L ${x + 8} 0 L ${x + 4} 16 L ${x} 16 Z`}
        fill="currentColor"
      />
    ))}
  </svg>
);
