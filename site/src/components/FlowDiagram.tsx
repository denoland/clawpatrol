import type { ComponentChildren } from "preact";

// Vertical flow with two stacked-card rows around the proxy:
// destinations on top, agents on the bottom. The stack glyphs hint
// "many of each kind", not just the one named.
export function FlowDiagram() {
  return (
    <div
      class="flex flex-col items-stretch w-full max-w-[380px] select-none"
      role="img"
      aria-label="Many agents on the bottom send requests through Claw Patrol to many destinations on top"
    >
      <ProductionNode />

      <Riser />

      <CenterNode
        label="Claw Patrol"
        sub="rules · approvals · credentials · analytics"
      />

      <Risers count={4} />

      <CardRow>
        <Card name="Claude" icon="/icons/anthropic.svg" />
        <Card name="Codex" icon="/icons/openai.svg" />
        <Card name="OpenClaw" icon="/icons/openclaw.svg" />
        <Card name="Others" />
      </CardRow>
    </div>
  );
}

function CardRow({ children }: { children: ComponentChildren }) {
  // pr-2 / pb-2 reserves room for the stacked-card shadows so they
  // don't touch the column edge or the arrows below.
  return (
    <div class="grid grid-cols-4 gap-3 w-full pr-2 pb-2">{children}</div>
  );
}

function ProductionNode() {
  return (
    <div
      class="squircle-md w-full bg-canvas border border-navy-200
        text-text px-5 py-5 text-center"
    >
      <div class="font-display font-bold text-xl leading-none">
        Production
      </div>
      <div
        class="font-mono text-[11px] uppercase tracking-wider mt-2
          text-text-muted text-balance"
      >
        postgres · clickhouse · k8s · aws · gcp · github · slack · notion · …
      </div>
    </div>
  );
}

function Riser() {
  return (
    <div class="w-full flex justify-center my-2">
      <svg
        width="16"
        height="28"
        viewBox="0 0 16 28"
        class="text-navy-300"
        aria-hidden="true"
      >
        <path
          d="M 8 28 V 5"
          stroke="currentColor"
          stroke-width="1.5"
          stroke-linecap="round"
          fill="none"
        />
        <path
          d="M 2 10 L 8 4 L 14 10"
          stroke="currentColor"
          stroke-width="1.5"
          stroke-linecap="round"
          stroke-linejoin="round"
          fill="none"
        />
      </svg>
    </div>
  );
}

function Card({ name, icon }: { name: string; icon?: string }) {
  // Two trailing box-shadows render as faded duplicate cards sitting
  // behind this one. Each pair: solid canvas fill + 1px navy ring.
  // Inline style — Tailwind's arbitrary shadow syntax doesn't compose
  // four space-separated shadows reliably.
  const stack =
    "4px 4px 0 0 var(--color-canvas)," +
    "4px 4px 0 1px var(--color-navy-200)," +
    "8px 8px 0 0 var(--color-canvas)," +
    "8px 8px 0 1px var(--color-navy-200)";
  return (
    <div
      class="squircle-md flex flex-col items-center justify-center gap-2
        px-2 py-3 bg-canvas border border-navy-200 min-w-0"
      style={{ boxShadow: stack }}
    >
      {icon ? (
        <img
          src={icon}
          alt=""
          class="w-6 h-6"
          aria-hidden="true"
        />
      ) : (
        <RobotGlyph />
      )}
      <div
        class="font-display font-semibold text-[11.5px] text-text-muted
          leading-tight text-center text-balance"
      >
        {name}
      </div>
    </div>
  );
}

// Parallel arrows between a card row and the proxy.
function Risers({ count }: { count: number }) {
  const w = 380;
  const h = 30;
  // 4 cols, gap-3 (12px). Centers in viewBox coords.
  const cellW = (w - (count - 1) * 12 - 8) / count; // -8 = pr-2 in row
  const cx = (i: number) => cellW / 2 + i * (cellW + 12);
  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      width="100%"
      height={h}
      class="text-navy-300 my-2"
      aria-hidden="true"
      preserveAspectRatio="none"
    >
      <g
        stroke="currentColor"
        stroke-width="1.5"
        stroke-linecap="round"
        stroke-linejoin="round"
        fill="none"
      >
        {Array.from({ length: count }, (_, i) => {
          const x = cx(i);
          return (
            <>
              <path d={`M ${x} ${h - 2} V 5`} />
              <path d={`M ${x - 5} 10 L ${x} 4 L ${x + 5} 10`} />
            </>
          );
        })}
      </g>
    </svg>
  );
}

function CenterNode({ label, sub }: { label: string; sub: string }) {
  // Light surface keyed to the header's bg-navy-100 so the proxy node
  // reads as the same brand surface; full Claw Patrol logo (icon +
  // wordmark) is the same public asset the header uses.
  return (
    <div
      class="squircle-md w-full bg-navy-100 text-text border border-navy
        px-5 py-5 text-center"
    >
      <img
        src="/claw-patrol-logo.svg"
        alt={label}
        class="h-8 sm:h-10 w-auto mx-auto"
      />
      <div
        class="font-mono text-[11px] uppercase tracking-wider mt-2
          text-text-muted"
      >
        {sub}
      </div>
    </div>
  );
}

function RobotGlyph() {
  return (
    <svg
      viewBox="0 0 24 24"
      class="w-6 h-6 text-navy-500"
      fill="none"
      stroke="currentColor"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path d="M 12 3 V 6" />
      <circle cx="12" cy="2" r="0.8" fill="currentColor" stroke="none" />
      <rect x="4" y="7" width="16" height="13" rx="2" />
      <circle cx="9" cy="13" r="1.2" fill="currentColor" stroke="none" />
      <circle cx="15" cy="13" r="1.2" fill="currentColor" stroke="none" />
      <path d="M 10 17 H 14" />
    </svg>
  );
}
