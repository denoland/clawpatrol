import { CrtOverlay } from "./CrtOverlay";
import { ScrollHint } from "./ScrollHint";
import { TypeLine } from "./TypeLine";

const AGENT = `┌─────────────────┐
│                 │
│     Agent(s)    │
│                 │
│                 │
│                 │
└─────────────────┘`;

const INTERNET = `┌────────────────────┐
│     Literally      │
│     the entire     │
│     internet       │
└────────────────────┘`;

const KEYS = `┌─────────────┐
│ Secret keys │
└─────────────┘`;

const TRACK = "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─";
const ACTIVE = "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─";

// Scattered key labels that proliferate around the Internet box
// Each has a position (ch, row) and a stagger index for timing
const SCATTERED_KEYS: {
  left: string;
  top: string;
  label: string;
  early?: boolean;
  dim?: boolean;
}[] = [
  // Along the line (appear while line is drawing) — the credentials leaking out
  { left: "22ch", top: "4.5", label: "Secret keys", early: true },
  { left: "28ch", top: "1.5", label: "Secret keys", early: true, dim: true },
  { left: "35ch", top: "5.2", label: "Secret keys", early: true },
  // Around the Internet box — the downstream damage
  { left: "45ch", top: "0.2", label: "PII" },
  { left: "57ch", top: "1.5", label: "Rogue emails", dim: true },
  { left: "49ch", top: "6.2", label: "Bank transfer" },
  { left: "68ch", top: "4.5", label: "Drop DB", dim: true },
  { left: "39ch", top: "6.8", label: "Hallucination" },
  { left: "55ch", top: "7.0", label: "Bad prompt", dim: true },
  { left: "63ch", top: "2.8", label: "Personal photos" },
  { left: "43ch", top: "8.0", label: "Secret keys", dim: true },
  { left: "59ch", top: "8.2", label: "Surprise purchase" },
  { left: "51ch", top: "-0.5", label: "Food delivery", dim: true },
  { left: "65ch", top: "6.2", label: "Data exfil" },
];

export function ScrollDiagram() {
  return (
    <div class="scroll-diagram">
      <div
        class="sticky top-0 h-screen flex flex-col items-center
          justify-center bg-linear-to-b from-crt-bg-light to-crt-bg-dark via-crt-bg px-8 overflow-hidden"
      >
        <CrtOverlay />

        <p
          class="text-xs uppercase tracking-[0.35em] mb-12
            text-crt-dim font-display font-medium z-10"
        >
          The problem
        </p>

        <div
          class="relative font-mono text-[clamp(0.5rem,calc(1vw+0.25rem),1.05rem)] z-10
            whitespace-pre leading-[1.6]
            [text-shadow:0_0_8px_currentColor]"
        >
          {/* Agent box */}
          <div class="dia-agent absolute text-crt-faint left-0 top-0">
            {AGENT}
          </div>

          {/* Dashed track */}
          <div class="absolute text-crt-faint/30 left-[19ch] top-[calc(3*1.6em)]">
            {TRACK}
          </div>

          {/* Active line — characters appear one by one */}
          <div class="absolute text-crt left-[19ch] top-[calc(3*1.6em)]">
            <TypeLine
              text={ACTIVE}
              timeline="--diagram"
              startPct={30}
              endPct={48}
            />
          </div>

          {/* Internet box */}
          <div class="dia-internet absolute text-crt-faint left-[43ch] top-[calc(1*1.6em)]">
            {INTERNET}
          </div>

          {/* Secret Keys — inside Agent box */}
          <div class="dia-keys-static absolute text-crt z-20 left-[2ch] top-[calc(3*1.6em)]">
            {KEYS}
          </div>

          {/* Scattered Secret Keys — proliferate around Internet box */}
          {SCATTERED_KEYS.map(({ left, top, label, early, dim }, i) => {
            let startPct: number;
            if (early) {
              startPct = 34 + i * 5;
            } else {
              startPct = 50 + (i - 3) * 2;
            }
            const endPct = startPct + 3;
            return (
              <span
                key={i}
                class={`dia-typed-char dia-scattered absolute z-20 ${
                  dim ? "text-rust/30" : "text-rust/70"
                }`}
                style={{
                  left,
                  top: `calc(${top} * 1.6em)`,
                  animationTimeline: "--diagram",
                  animationRange: `cover ${startPct}% cover ${endPct}%`,
                }}
              >
                {label}
              </span>
            );
          })}

          {/* Spacer */}
          <div class="invisible">{`${"".padEnd(78, " ")}\n`.repeat(9)}</div>
        </div>

        <div class="relative h-6 mt-10 w-full max-w-md z-10 text-center text-[clamp(0.875rem,1.1vw,1.125rem)] text-crt-dim/70 font-mono">
          <p class="dia-cap dia-cap-1 absolute inset-x-0 text-center">
            Your agent needs real credentials to do real work
          </p>
          <p class="dia-cap dia-cap-2 absolute inset-x-0 text-center">
            So you hand it your secret keys
          </p>
          <p class="dia-cap dia-cap-3 absolute inset-x-0 text-center">
            One prompt injection, one buggy loop, one logged error…
          </p>
          <p class="dia-cap dia-cap-4 absolute inset-x-0 text-center">
            Your agents could do anything
          </p>
        </div>

        <ScrollHint />
      </div>
    </div>
  );
}
