import { CrtOverlay } from "./CrtOverlay";
import { ScrollHint } from "./ScrollHint";
import { TypeBlock, TypeLine } from "./TypeLine";

const AGENT = `┌──────────┐
│          │
│ Agent(s) │
│          │
└──────────┘`;

const CLAWPATROL = `┌──────────────┐
│              │
│  CLAWPATROL  │
│              │
└──────────────┘`;

const APPROVED = `┌──────────────┐
│ Enabled      │
│ integrations │
└──────────────┘`;

const REST = `┌──────────────┐
│  Rest of the │
│  internet    │
└──────────────┘`;

const KEYS = `┌────────────┐
│ Secrets -> │
└────────────┘`;

export function ScrollDiagramSolution() {
  return (
    <div class="scroll-diagram-sol">
      <div
        class="sticky top-0 h-screen flex flex-col items-center
          justify-center bg-crt-bg px-8 overflow-hidden"
      >
        <CrtOverlay />

        <p
          class="text-xs uppercase tracking-[0.35em] mb-12
            text-crt-dim font-display font-medium z-10"
        >
          The solution
        </p>

        <div
          class="relative font-mono text-[clamp(0.5rem,calc(1vw+0.25rem),1.05rem)] z-10
            whitespace-pre leading-[1.6]
            [text-shadow:0_0_8px_currentColor]"
        >
          {/* === DASHED TRACKS === */}

          {/* Track: Agent → Claw Patrol */}
          <div class="absolute text-crt-faint/30 left-[10ch] top-[calc(4*1.6em)]">
            {"─ ─ ─"}
          </div>

          {/* Track: Claw Patrol right edge → Approved */}
          <div class="absolute text-crt-faint/30 left-[30ch] top-[calc(4*1.6em)]">
            {"─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─"}
          </div>

          {/* Track: ┬ at Claw Patrol bottom center, then vertical drop */}
          <div class="absolute text-crt-faint/30 z-20 left-[22ch] top-[calc(6*1.6em)]">
            {"┬\n│\n│\n└ ─ ─ ─ ─ ─ ─ ─"}
          </div>

          {/* === ACTIVE LINES (typed char by char) === */}

          {/* Active: Agent → Claw Patrol */}
          <div class="absolute text-crt left-[10ch] top-[calc(4*1.6em)]">
            <TypeLine
              text={"─ ─ ─"}
              timeline="--diagram-sol"
              startPct={28}
              endPct={36}
            />
          </div>

          {/* Active: Claw Patrol → Secrets → Approved */}
          <div class="absolute text-crt left-[30ch] top-[calc(4*1.6em)]">
            <TypeLine
              text={"─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─"}
              timeline="--diagram-sol"
              startPct={36}
              endPct={46}
            />
          </div>

          {/* Active: lower branch (red) — drop then └ right, ending with x */}
          <div class="absolute text-[#ef4444] left-[22ch] top-[calc(6*1.6em)]">
            <TypeBlock
              text={"┬\n│\n│\n└ ─ ─ ─ ─ ─ ─ ─ x"}
              timeline="--diagram-sol"
              startPct={70}
              endPct={80}
            />
          </div>

          {/* === ACCESS DENIED — below Rest of Internet === */}
          <div class="dia2-blocked absolute z-30 left-[39ch] top-[calc(12.5*1.6em)]">
            <span
              class="font-mono font-bold whitespace-nowrap tracking-wider text-[#fca5a5]
                [text-shadow:0_0_12px_rgba(252,165,165,0.6),0_0_4px_rgba(252,165,165,0.3)]"
            >
              ✕ ACCESS DENIED
            </span>
          </div>

          {/* === NODE BOXES === */}

          <div class="dia2-agent absolute text-crt-faint bg-crt-bg z-10 left-0 top-[calc(2*1.6em)]">
            {AGENT}
          </div>

          <div class="dia2-clawpatrol absolute text-persimmon bg-crt-bg z-10 left-[16ch] top-[calc(2*1.6em)]">
            {CLAWPATROL}
          </div>

          {/* Secrets — centered vertically on the line */}
          <div class="dia2-keys absolute text-crt bg-crt-bg z-20 left-[33ch] top-[calc(3*1.6em)]">
            {KEYS}
          </div>

          <div class="absolute text-crt-faint bg-crt-bg z-10 left-[52ch] top-[calc(2.5*1.6em)]">
            {APPROVED}
          </div>

          <div class="absolute text-crt-faint/40 bg-crt-bg z-10 left-[39ch] top-[calc(8*1.6em)]">
            {REST}
          </div>

          {/* Spacer */}
          <div class="invisible">{`${"".padEnd(67, " ")}\n`.repeat(13)}</div>
        </div>

        {/* Captions */}
        <div class="relative h-6 mt-10 w-full max-w-md z-10 text-center text-[clamp(0.875rem,1.1vw,1.125rem)] text-crt-dim/70 font-mono">
          <p class="dia2-cap dia2-cap-1 absolute inset-x-0 text-center">
            Same agents, same APIs, same code
          </p>
          <p class="dia2-cap dia2-cap-2 absolute inset-x-0 text-center">
            But the secrets live outside the agent
          </p>
          <p class="dia2-cap dia2-cap-3 absolute inset-x-0 text-center">
            Agents send placeholders; Claw Patrol injects real credentials at the
            edge
          </p>
          <p class="dia2-cap dia2-cap-4 absolute inset-x-0 text-center">
            Agents can't leak what they can't see
          </p>
          <p class="dia2-cap dia2-cap-5 absolute inset-x-0 text-center">
            Every request is logged
          </p>
          <p class="dia2-cap dia2-cap-6 absolute inset-x-0 text-center">
            Secrets go only to approved destinations
          </p>
        </div>

        <ScrollHint timeline="--diagram-sol" />
      </div>
    </div>
  );
}
