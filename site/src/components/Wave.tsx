type WaveArgs = {
  /** Color of the section above (fills the wavy upper region). */
  topColor: string;
  /** Color of the section below (fills the area beneath the wave). */
  bottomColor: string;
  /** Tailwind height utility for the divider band. */
  height?: string;
};

export function Wave({ topColor, bottomColor, height = "h-32" }: WaveArgs) {
  return (
    <div
      class={`relative w-full overflow-clip ${height}`}
      style={{ background: bottomColor }}
      aria-hidden="true"
    >
      {/* `overflow-clip` (not `overflow-hidden`) on the outer: it visually
         clips the 200%-wide SVGs and any vertical bleed from the spread
         animation, but does NOT make this element a scroll container — so
         `animation-timeline: view()` on the inner divs still observes
         document scroll progress, not the (always-zero) progress within
         a clipped wrapper. */}
      {/* Back row — deepest baseline, mostly navy blend, slowest drift. */}
      <div class="wave-spread-back absolute inset-0">
        <svg
          class="block h-full w-[200%] motion-safe:animate-wave-drift-slow"
          viewBox="0 0 2400 60"
          preserveAspectRatio="none"
        >
          <path
            d="M0,0 L2400,0 L2400,46 C2360,58 2290,58 2250,46 C2210,58 2140,58 2100,46 C2060,58 1990,58 1950,46 C1910,58 1840,58 1800,46 C1760,58 1690,58 1650,46 C1610,58 1540,58 1500,46 C1460,58 1390,58 1350,46 C1310,58 1240,58 1200,46 C1160,58 1090,58 1050,46 C1010,58 940,58 900,46 C860,58 790,58 750,46 C710,58 640,58 600,46 C560,58 490,58 450,46 C410,58 340,58 300,46 C260,58 190,58 150,46 C110,58 40,58 0,46 Z"
            style={{
              fill: `color-mix(in oklch, ${topColor} 35%, ${bottomColor})`,
            }}
          />
        </svg>
      </div>
      {/* Mid row — middle baseline, even blend, medium drift. */}
      <div class="wave-spread-mid absolute inset-0">
        <svg
          class="block h-full w-[200%] motion-safe:animate-wave-drift-medium"
          viewBox="0 0 2400 60"
          preserveAspectRatio="none"
        >
          <path
            d="M0,0 L2400,0 L2400,33 C2360,45 2290,45 2250,33 C2210,45 2140,45 2100,33 C2060,45 1990,45 1950,33 C1910,45 1840,45 1800,33 C1760,45 1690,45 1650,33 C1610,45 1540,45 1500,33 C1460,45 1390,45 1350,33 C1310,45 1240,45 1200,33 C1160,45 1090,45 1050,33 C1010,45 940,45 900,33 C860,45 790,45 750,33 C710,45 640,45 600,33 C560,45 490,45 450,33 C410,45 340,45 300,33 C260,45 190,45 150,33 C110,45 40,45 0,33 Z"
            style={{
              fill: `color-mix(in oklch, ${topColor} 70%, ${bottomColor})`,
            }}
          />
        </svg>
      </div>
      {/* Front row — shallowest baseline, pure topColor, fast drift. */}
      <div class="wave-spread-front absolute inset-0">
        <svg
          class="block h-full w-[200%] motion-safe:animate-wave-drift"
          viewBox="0 0 2400 60"
          preserveAspectRatio="none"
        >
          <path
            d="M0,0 L2400,0 L2400,16 C2360,26 2290,26 2250,16 C2210,26 2140,26 2100,16 C2060,26 1990,26 1950,16 C1910,26 1840,26 1800,16 C1760,26 1690,26 1650,16 C1610,26 1540,26 1500,16 C1460,26 1390,26 1350,16 C1310,26 1240,26 1200,16 C1160,26 1090,26 1050,16 C1010,26 940,26 900,16 C860,26 790,26 750,16 C710,26 640,26 600,16 C560,26 490,26 450,16 C410,26 340,26 300,16 C260,26 190,26 150,16 C110,26 40,26 0,16 Z"
            fill={topColor}
          />
        </svg>
      </div>
    </div>
  );
}
