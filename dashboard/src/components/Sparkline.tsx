// slop.dev-style smooth area line chart. Stable width regardless of
// data length (pads with zeros to fixed buckets). On `data` change the
// path lerps from the previous shape to the new one over ~400ms via
// rAF instead of snapping — keeps per-poll updates from looking like
// a step jump.

import { useEffect, useRef, useState } from "react";

const TRANSITION_MS = 400;

export function Sparkline({
  data,
  width = 120,
  height = 18,
  buckets = 30,
  color = "var(--color-success-500)",
}: {
  data?: number[];
  width?: number;
  height?: number;
  buckets?: number;
  color?: string;
}) {
  const target = padTo(data ?? [], buckets);
  const [displayed, setDisplayed] = useState<number[]>(target);
  const fromRef = useRef<number[]>(target);
  const startRef = useRef<number>(0);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    // First render or identical → no animation.
    if (arraysEqual(fromRef.current, target)) return;
    const from = fromRef.current.slice();
    const to = target;
    startRef.current = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - startRef.current) / TRANSITION_MS);
      const eased = easeOutCubic(t);
      const next: number[] = Array.from({ length: to.length });
      for (let i = 0; i < to.length; i++) {
        const a = from[i] ?? 0;
        const b = to[i] ?? 0;
        next[i] = a + (b - a) * eased;
      }
      setDisplayed(next);
      if (t < 1) {
        rafRef.current = requestAnimationFrame(tick);
      } else {
        fromRef.current = to;
        rafRef.current = null;
      }
    };
    if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
      // Snap fromRef to last-rendered so a re-trigger lerps from there.
      fromRef.current = displayed;
    };
    // displayed intentionally excluded — including it would re-run the
    // effect every frame and reset the animation.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target.join(",")]);

  const padded = displayed;
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

function arraysEqual(a: number[], b: number[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function easeOutCubic(t: number): number {
  return 1 - Math.pow(1 - t, 3);
}
