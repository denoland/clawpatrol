type WaveArgs = {
  /** Color of the section above (fills the wavy upper region). */
  topColor: string;
  /** Color of the section below (fills the area beneath the wave). */
  bottomColor: string;
  /** Tailwind height utility for the divider band. */
  height?: string;
};

export function Wave({
  topColor,
  bottomColor,
  height = "h-24",
}: WaveArgs) {
  return (
    <div
      class={`relative w-full overflow-hidden ${height}`}
      style={{ background: bottomColor }}
      aria-hidden="true"
    >
      {/* Back row — deepest baseline, mostly navy blend, slow drift. */}
      <svg
        class="absolute inset-0 block h-full w-[200%] motion-safe:animate-wave-drift-slow"
        viewBox="0 0 2400 60"
        preserveAspectRatio="none"
      >
        <path
          d="M0,0 L2400,0 L2400,46 C2347,58 2253,58 2200,46 C2147,58 2053,58 2000,46 C1947,58 1853,58 1800,46 C1747,58 1653,58 1600,46 C1547,58 1453,58 1400,46 C1347,58 1253,58 1200,46 C1147,58 1053,58 1000,46 C947,58 853,58 800,46 C747,58 653,58 600,46 C547,58 453,58 400,46 C347,58 253,58 200,46 C147,58 53,58 0,46 Z"
          style={{
            fill: `color-mix(in oklch, ${topColor} 35%, ${bottomColor})`,
          }}
        />
      </svg>
      {/* Mid row — middle baseline, even blend, medium drift. */}
      <svg
        class="absolute inset-0 block h-full w-[200%] motion-safe:animate-wave-drift-medium"
        viewBox="0 0 2400 60"
        preserveAspectRatio="none"
      >
        <path
          d="M0,0 L2400,0 L2400,33 C2347,45 2253,45 2200,33 C2147,45 2053,45 2000,33 C1947,45 1853,45 1800,33 C1747,45 1653,45 1600,33 C1547,45 1453,45 1400,33 C1347,45 1253,45 1200,33 C1147,45 1053,45 1000,33 C947,45 853,45 800,33 C747,45 653,45 600,33 C547,45 453,45 400,33 C347,45 253,45 200,33 C147,45 53,45 0,33 Z"
          style={{
            fill: `color-mix(in oklch, ${topColor} 70%, ${bottomColor})`,
          }}
        />
      </svg>
      {/* Front row — shallowest baseline, pure topColor, fast drift. */}
      <svg
        class="absolute inset-0 block h-full w-[200%] motion-safe:animate-wave-drift"
        viewBox="0 0 2400 60"
        preserveAspectRatio="none"
      >
        <path
          d="M0,0 L2400,0 L2400,20 C2347,32 2253,32 2200,20 C2147,32 2053,32 2000,20 C1947,32 1853,32 1800,20 C1747,32 1653,32 1600,20 C1547,32 1453,32 1400,20 C1347,32 1253,32 1200,20 C1147,32 1053,32 1000,20 C947,32 853,32 800,20 C747,32 653,32 600,20 C547,32 453,32 400,20 C347,32 253,32 200,20 C147,32 53,32 0,20 Z"
          fill={topColor}
        />
      </svg>
    </div>
  );
}
