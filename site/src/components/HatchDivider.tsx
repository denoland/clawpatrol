type HatchDividerProps = {
  /** Background of the divider itself — matches the section above. */
  topColor: string;
  /** Hatch line color — matches the section below so the band reads as
   *  the next section bleeding upward through cream. */
  bottomColor: string;
  /** Divider height in pixels (drives the line-positions curve). */
  height?: number;
  /** Number of hatch lines. More lines = smoother density ramp. */
  lineCount?: number;
};

// Lines are placed at y = H * (1 - (1 - t)^k) for t in [0..1]. With
// k > 1 the function is concave: spacing is wide at the top, tight at
// the bottom, so the last few lines pile up into what reads as a solid
// edge against the section below.
const CURVE = 2;

export function HatchDivider({
  topColor,
  bottomColor,
  height = 128,
  lineCount = 23,
}: HatchDividerProps) {
  const positions = Array.from({ length: lineCount }, (_, i) => {
    const t = i / (lineCount - 1);
    return height * (1 - Math.pow(1 - t, CURVE));
  });

  return (
    <svg
      aria-hidden="true"
      class="block w-full"
      width="100%"
      height={height}
      viewBox={`0 0 100 ${height}`}
      preserveAspectRatio="none"
      style={{ background: topColor }}
      shape-rendering="crispEdges"
    >
      {positions.map((y, i) => (
        <line
          key={i}
          x1="0"
          y1={y}
          x2="100"
          y2={y}
          stroke={bottomColor}
          vectorEffect="non-scaling-stroke"
          style={{ strokeWidth: i / 3 }}
        />
      ))}
    </svg>
  );
}
