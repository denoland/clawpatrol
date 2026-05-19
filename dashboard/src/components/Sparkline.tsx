// slop.dev-style smooth area line chart. Stable width regardless of
// data length (pads with zeros to fixed buckets). On `data` change a
// scroll animation slides the existing line left by one bucket while
// the new value enters from the right — the shape never reconstructs
// in place, so per-poll updates read as motion instead of a jump.

import { useEffect, useRef, useState } from "react";

const SCROLL_MS = 800;

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
  const step = buckets > 1 ? width / (buckets - 1) : 0;

  // displayed is the array we actually plot. Idle: length === buckets.
  // During the scroll animation: length === buckets + 1, with the new
  // rightmost point sitting at x = buckets*step (just past the right
  // edge of the viewBox) and tx animating from 0 to -step. When the
  // animation completes we swap to the new target and reset tx.
  const [displayed, setDisplayed] = useState<number[]>(target);
  const [tx, setTx] = useState(0);
  const prevTargetRef = useRef<number[]>(target);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    if (arraysEqual(prevTargetRef.current, target)) return;
    const prev = prevTargetRef.current;
    const newest = target.length > 0 ? target[target.length - 1] : 0;
    // Pre-animation paint: render prev + newest at tx=0 so the new
    // point is offscreen-right when the slide starts.
    setDisplayed([...prev, newest]);
    setTx(0);
    if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
    rafRef.current = requestAnimationFrame(() => {
      const start = performance.now();
      const tick = (now: number) => {
        const t = Math.min(1, (now - start) / SCROLL_MS);
        const eased = easeOutCubic(t);
        setTx(-step * eased);
        if (t < 1) {
          rafRef.current = requestAnimationFrame(tick);
          return;
        }
        setDisplayed(target);
        setTx(0);
        prevTargetRef.current = target;
        rafRef.current = null;
      };
      rafRef.current = requestAnimationFrame(tick);
    });
    return () => {
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
    };
    // target.join(",") collapses the array to a stable dep key.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target.join(",")]);

  const max = Math.max(1, ...displayed);
  const pts = displayed.map((v, i) => {
    const x = i * step;
    const y = height - (v / max) * (height - 1) - 0.5;
    return [x, y] as const;
  });
  const linePath =
    pts.length > 0 ? "M " + pts.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" L ") : "";
  const lastX = pts.length > 0 ? pts[pts.length - 1][0] : 0;
  const fillPath = linePath + ` L ${lastX.toFixed(1)},${height} L 0,${height} Z`;

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className="block"
      preserveAspectRatio="none"
      overflow="hidden"
    >
      <g transform={`translate(${tx},0)`}>
        <path d={fillPath} fill={color} opacity={0.15} />
        <path
          d={linePath}
          fill="none"
          stroke={color}
          strokeWidth={1.25}
          strokeLinejoin="round"
          strokeLinecap="round"
        />
      </g>
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
