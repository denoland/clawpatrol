import type { ComponentChildren } from "preact";
import { HclCode } from "../components/HclCode";
import { SectionLabel } from "../components/SectionLabel";
import { TerminalFrame } from "../components/TerminalFrame";
import { snippet } from "../lib/example";
import { approver_human, approver_llm } from "../lib/examples";

/* ──────────────────────────────────────────────────────────────────────
   Approvers — deepens the `require_llm` and `require_human` verdicts
   that RulesSection introduces.

   Both cards share an identical skeleton:
     1. header (title + verdict code)
     2. one-line pitch
     3. HCL snippet (top half)
     4. a stylized "in practice" panel (bottom half) — same 3-row flow
        for both: incoming → response → verdict pill
   ──────────────────────────────────────────────────────────────────── */

const LLM_CONFIG = snippet(approver_llm);
const HUMAN_CONFIG = snippet(approver_human);

/* ── Shared diagram primitives ─────────────────────────────────────── */

function DiagramFrame({ children }: { children: ComponentChildren }) {
  return (
    <div class="bg-canvas-muted border w-full border-rust-200/60 squircle-md p-4 flex flex-col gap-3">
      {children}
    </div>
  );
}

function ConnectingLine() {
  return (
    <div class="w-full flex justify-center my-2" aria-hidden="true">
      <svg width="16" height="28" viewBox="0 0 16 28" class="text-navy/40">
        <path
          d="M 8 0 V 23"
          stroke="currentColor"
          stroke-width="1.5"
          stroke-linecap="round"
          fill="none"
        />
        <path
          d="M 2 18 L 8 24 L 14 18"
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

/* ── LLM judge: request → model reasoning → verdict ────────────────── */

function LlmDiagram() {
  return (
    <DiagramFrame>
      <div class="bg-canvas px-3 py-2 font-mono text-[12px] ">
        <div class="text-text-subtle text-[10px] uppercase tracking-[0.18em] mb-1">
          incoming
        </div>
        <code class="text-text">
          SELECT id, name, <span class="text-rust font-bold">api_key</span> FROM
          users LIMIT 10
        </code>
      </div>

      <div class="flex items-center gap-2">
        <div class="shrink-0 w-7 h-7 rounded-full bg-rust-200 flex items-center justify-center text-[11px] font-display font-bold text-rust-800">
          AI
        </div>
        <div class="bg-canvas border border-rust-100  px-3 py-2 text-[12px]  text-text-muted">
          <span class="text-rust font-bold">✗ Denied</span> — projects{" "}
          <code class="text-text font-mono">api_key</code>, a secret-bearing
          column.
        </div>
      </div>
    </DiagramFrame>
  );
}

/* ── Human In The Loop: Slack ping → human reply → verdict ─────────── */

function HumanDiagram() {
  return (
    <DiagramFrame>
      <div class="text-text-subtle text-[10px] uppercase tracking-[0.18em] pb-2 mb-2 border-b border-rust-100 leading-none">
        #agent-ops
      </div>

      <div class="flex gap-2">
        <div class="shrink-0 w-8 h-8 squircle-md bg-navy-700 flex items-center justify-center text-[11px] font-display font-bold text-canvas">
          CP
        </div>
        <div class="flex-1 min-w-0">
          <div class="flex items-baseline gap-1.5 leading-none">
            <span class="font-bold text-text text-[13px]">Claw Patrol</span>
            <span class="text-text-subtle text-[10px]">APP</span>
            <span class="text-text-subtle text-[10px]">1:42 PM</span>
          </div>
          <div class="text-[12px] text-text-muted mt-0.5">
            <span class="text-text font-bold">prod-codex</span> wants to DELETE{" "}
            <code class="text-text font-mono">/repos/acme/checkout</code>
          </div>
        </div>
      </div>

      <div class="flex gap-2">
        <div class="shrink-0 w-8 h-8 squircle-md bg-rust-300 flex items-center justify-center text-[11px] font-display font-bold text-rust-900">
          JC
        </div>
        <div class="flex-1 min-w-0">
          <div class="flex items-baseline gap-1.5 leading-none">
            <span class="font-bold text-text text-[13px]">Josh</span>
            <span class="text-text-subtle text-[10px]">1:42 PM</span>
          </div>
          <div class="text-[12px] text-text mt-0.5">approved</div>
        </div>
      </div>

      <div class="flex gap-2">
        <div class="shrink-0 w-8 h-8 squircle-md bg-navy-700 flex items-center justify-center text-[11px] font-display font-bold text-canvas">
          CP
        </div>
        <div class="flex-1 min-w-0">
          <div class="flex items-baseline gap-1.5 leading-none">
            <span class="font-bold text-text text-[13px]">Claw Patrol</span>
            <span class="text-text-subtle text-[10px]">APP</span>
            <span class="text-text-subtle text-[10px]">1:42 PM</span>
          </div>
          <div class="text-[12px] text-text-muted mt-0.5">
            <span class="text-rust font-bold">✓ Allowed</span> — forwarded to
            upstream (14s).
          </div>
        </div>
      </div>
    </DiagramFrame>
  );
}

/* ── Card shell ────────────────────────────────────────────────────── */

function ApproverCard({
  title,
  verdict,
  pitch,
  config,
}: {
  title: string;
  verdict: string;
  pitch: string;
  config: string;
}) {
  return (
    <article class="isolate min-w-0 bg-transparent relative lg:mb-16">
      <div className="relative z-10 flex flex-col gap-4">
        <header class="flex items-baseline justify-between">
          <h4 class="text-3xl font-display text-text">{title}</h4>
          <code class="text-[10px] font-mono text-text-subtle">{verdict}</code>
        </header>
        <p class="text-sm text-text-muted">{pitch}</p>
        <TerminalFrame class="block p-4 squircle-lg lg:-mb-16">
          <HclCode
            source={config}
            class="text-[12px] font-mono text-canvas overflow-x-auto whitespace-pre"
          />
        </TerminalFrame>
      </div>
    </article>
  );
}

/* ── "OR" divider between the two approver cards ───────────────────── */

function OrDivider() {
  return (
    <div class="flex justify-center relative lg:self-center my-8 border-8 border-canvas bg-rust px-3 py-1 squircle-lg mx-auto w-max z-10">
      <span class="font-mono uppercase text-canvas text-base">-or-</span>
    </div>
  );
}

export function ApproversSection() {
  return (
    <section class="bg-rust-50 py-24 sm:py-32">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <SectionLabel class="ml-0">Approval flows</SectionLabel>

        <div class="max-w-3xl mb-14">
          <h3 class="text-4xl sm:text-5xl md:text-6xl font-display text-balance mb-5 text-text">
            Put a <span className="text-rust">human in the loop</span>, or
            double-check with another agent
          </h3>
          <p class="text-base  text-text-muted">
            Defer ambiguous requests to a model with your prompt, or a real
            human via Slack. You decide which one runs when.
          </p>
        </div>

        <div class="grid grid-cols-1 gap-8 lg:grid-cols-[1fr_auto_1fr] lg:gap-4">
          <div class="flex flex-col min-w-0">
            <ApproverCard
              title="LLM judge"
              verdict="require_llm"
              pitch="A model with a custom prompt votes on each request. Verdicts are cached so it doesn’t re-bill."
              config={LLM_CONFIG}
            />
            <ConnectingLine />
            <LlmDiagram />
          </div>
          <div className="relative flex flex-col justify-center items-center">
            <div class="w-full h-0 border-t left-0 top-1/2 absolute lg:w-0 lg:border-r lg:border-t-0 border-dashed border-canvas-dark lg:h-full lg:left-1/2 lg:top-0"></div>
            <OrDivider />
          </div>
          <div class="flex flex-col min-w-0">
            <ApproverCard
              title="Human In The Loop"
              verdict="require_human"
              pitch="A person votes in Slack, the dashboard, or your own webhook. Times out closed if no one’s home."
              config={HUMAN_CONFIG}
            />
            <ConnectingLine />
            <HumanDiagram />
          </div>
        </div>
      </div>
    </section>
  );
}
