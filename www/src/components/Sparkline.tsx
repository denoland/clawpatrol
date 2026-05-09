// slop.dev-style smooth area line chart. Stable width regardless of
// data length (pads with zeros to fixed buckets).

export function Sparkline({
  data,
  width = 120,
  height = 18,
  buckets = 30,
  color = "#16a34a",
}: {
  data?: number[];
  width?: number;
  height?: number;
  buckets?: number;
  color?: string;
}) {
  const padded = padTo(data ?? [], buckets);
  const max = Math.max(1, ...padded);
  const step = padded.length === 1 ? 0 : width / (padded.length - 1);

  const pts = padded.map((v, i) => {
    const x = i * step;
    const y = height - (v / max) * (height - 1) - 0.5;
    return [x, y] as const;
  });

  const linePath = "M " + pts.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" L ");
  const fillPath = linePath + ` L ${width},${height} L 0,${height} Z`;

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className="block"
      preserveAspectRatio="none"
    >
      <path d={fillPath} fill={color} opacity={0.15} />
      <path
        d={linePath}
        fill="none"
        stroke={color}
        strokeWidth={1.25}
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}

function padTo(a: number[], n: number): number[] {
  if (a.length >= n) return a.slice(-n);
  return Array.from({ length: n - a.length }, () => 0).concat(a);
}
