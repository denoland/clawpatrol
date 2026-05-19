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
    <div class="bg-canvas-muted border border-rust-200/60 squircle-md p-4 flex flex-col gap-3">
      {children}
    </div>
  );
}

function VerdictPill({
  label,
  kind = "deny",
}: {
  label: string;
  kind?: "deny" | "allow";
}) {
  const styles =
    kind === "allow" ? "bg-rust text-text" : "bg-navy-700 text-canvas";
  return (
    <div class="flex justify-center">
      <span
        class={`inline-block text-[10px] uppercase tracking-[0.25em]
          font-display font-bold px-3 py-1.5 ${styles}`}
      >
        verdict · {label}
      </span>
    </div>
  );
}

/* ── LLM judge: request → model reasoning → verdict ────────────────── */

function LlmDiagram() {
  return (
    <DiagramFrame>
      <div class="bg-canvas  px-3 py-2 font-mono text-[12px] ">
        <div class="text-text-subtle text-[10px] uppercase tracking-[0.18em] mb-1">
          incoming
        </div>
        <code class="text-text">
          POST /tickets/reply {"{ "}body: "RTFM you moron"{" }"}
        </code>
      </div>

      <div class="flex items-start gap-2">
        <div class="shrink-0 w-7 h-7 rounded-full bg-rust-200 flex items-center justify-center text-[11px] font-display font-bold text-rust-800">
          AI
        </div>
        <div class="bg-canvas border border-rust-100  px-3 py-2 text-[12px]  text-text-muted">
          Reply body contains banned term{" "}
          <code class="text-text font-mono">moron</code>.
        </div>
      </div>

      <VerdictPill label="deny · 240ms · cached" kind="deny" />
    </DiagramFrame>
  );
}

/* ── Human In The Loop: Slack ping → human reply → verdict ─────────── */

function HumanDiagram() {
  return (
    <DiagramFrame>
      <div class="flex items-start gap-2">
        <div class="shrink-0 w-7 h-7 rounded-full bg-navy-700 flex items-center justify-center text-[11px] font-display font-bold text-canvas">
          CP
        </div>
        <div class="bg-canvas border border-rust-100  px-3 py-2 text-[12px] ">
          <div class="text-text-subtle text-[10px] uppercase tracking-[0.18em] mb-1">
            #agent-ops
          </div>
          <div class="text-text-muted">
            <span class="text-text font-bold">prod-codex</span> wants to DELETE{" "}
            <code class="text-text font-mono">/repos/acme/checkout</code>
          </div>
        </div>
      </div>

      <div class="flex items-start gap-2 flex-row-reverse">
        <div class="shrink-0 w-7 h-7 rounded-full bg-rust-300 flex items-center justify-center text-[11px] font-display font-bold text-rust-900">
          JC
        </div>
        <div class="bg-rust-100 border border-rust-200  px-3 py-2 text-[12px]  text-text">
          ✓ approve — that's fine
        </div>
      </div>

      <VerdictPill label="allow · 14s" kind="allow" />
    </DiagramFrame>
  );
}

/* ── Card shell ────────────────────────────────────────────────────── */

function ApproverCard({
  title,
  verdict,
  pitch,
  config,
  diagram,
}: {
  title: string;
  verdict: string;
  pitch: string;
  config: string;
  diagram: ComponentChildren;
}) {
  return (
    <article class="isolate min-w-0 bg-transparent relative lg:p-8 xl:p-12">
      <div className="hidden w-full h-full border lg:block border-navy  z-10 absolute inset-0"></div>
      <div className="hidden lg:block absolute w-full h-full top-1 left-1 bg-horizontal-stripes  z-0" />
      <div className="relative z-10 flex flex-col gap-4">
        <header class="flex items-baseline justify-between">
          <h4 class="text-3xl font-display text-text">{title}</h4>
          <code class="text-[10px] font-mono text-text-subtle">{verdict}</code>
        </header>
        <p class="text-sm  text-text-muted">{pitch}</p>
        <TerminalFrame class="block p-4">
          <HclCode
            source={config}
            class="text-[12px] font-mono text-canvas overflow-x-auto whitespace-pre"
          />
        </TerminalFrame>
        {diagram}
      </div>
    </article>
  );
}

/* ── "OR" divider between the two approver cards ───────────────────── */

function OrDivider() {
  return (
    <div class="flex justify-center lg:self-center">
      <span class="font-display font-black uppercase text-rust text-2xl">
        - or -
      </span>
    </div>
  );
}

export function ApproversSection() {
  return (
    <section class="bg-rust-50 py-24 sm:py-32">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <SectionLabel>Approval flows</SectionLabel>

        <div class="max-w-3xl mb-14">
          <h3 class="text-4xl sm:text-5xl md:text-6xl font-display text-balance mb-5 text-text">
            Humans, models, <span class="text-rust">your call</span>
          </h3>
          <p class="text-base  text-text-muted">
            Defer the ambiguous requests. A model with your prompt, or a person
            in Slack. You decide which one runs when.
          </p>
        </div>

        <div class="grid grid-cols-1 gap-8 lg:grid-cols-[1fr_auto_1fr] lg:gap-4">
          <ApproverCard
            title="LLM judge"
            verdict="require_llm"
            pitch="A model with a custom prompt votes on each request. Verdicts are cached so it doesn't re-bill."
            config={LLM_CONFIG}
            diagram={<LlmDiagram />}
          />
          <OrDivider />
          <ApproverCard
            title="Human In The Loop"
            verdict="require_human"
            pitch="A person votes in Slack, the dashboard, or your own webhook. Times out closed if no one's home."
            config={HUMAN_CONFIG}
            diagram={<HumanDiagram />}
          />
        </div>
      </div>
    </section>
  );
}
