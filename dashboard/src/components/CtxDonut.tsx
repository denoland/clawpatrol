// Donut showing context-window usage. Threshold colors track the
// semantic state tokens: danger ≥90%, butter (warning) 70-89%, navy
// (info) <70%.

export function CtxDonut({ used, max, size = 18 }: { used?: number; max?: number; size?: number }) {
  if (!used || !max) return null;
  const pct = Math.min(1, used / max);
  const color =
    pct >= 0.9
      ? "var(--color-danger-400)"
      : pct >= 0.7
        ? "var(--color-butter-500)"
        : "var(--color-navy-300)";
  const r = (size - 3) / 2;
  const c = size / 2;
  const circ = 2 * Math.PI * r;
  const off = circ * (1 - pct);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="block">
      <circle cx={c} cy={c} r={r} fill="none" stroke="var(--color-canvas-dark)" strokeWidth={2.5} />
      <circle
        cx={c}
        cy={c}
        r={r}
        fill="none"
        stroke={color}
        strokeWidth={2.5}
        strokeLinecap="round"
        strokeDasharray={circ}
        strokeDashoffset={off}
        transform={`rotate(-90 ${c} ${c})`}
      />
    </svg>
  );
}
