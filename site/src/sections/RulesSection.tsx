import { HclCode } from "../components/HclCode";
import { SectionLabel } from "../components/SectionLabel";
import { snippet } from "../lib/example";
import { rules_block } from "../lib/examples";

/* ──────────────────────────────────────────────────────────────────────
   The "rules" pillar — frames the policy engine with a real HCL
   snippet. The deferred verdicts (LLM judge, human approval) are
   covered next door in ApproversSection, so this section stays
   focused on rule authoring.
   ──────────────────────────────────────────────────────────────────── */

function RuleCodeBlock() {
  return (
    <HclCode
      source={snippet(rules_block)}
      class="min-w-0 text-[13px] sm:text-sm font-mono
        bg-navy text-canvas/85 squircle-md p-6 overflow-x-auto
        border border-navy-700 whitespace-pre"
    />
  );
}

export function RulesSection() {
  return (
    <section class="bg-canvas-muted py-24 sm:py-32">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <SectionLabel>Approval rules</SectionLabel>

        <div class="grid grid-cols-1 lg:grid-cols-[2fr_3fr] gap-8 lg:gap-16 xl:gap-32 items-start">
          <div class="min-w-0">
            <h3 class="text-4xl sm:text-5xl md:text-6xl lg:text-[3.25rem] font-display font-bold text-balance mb-6 text-text">
              You write the rules.{" "}
              <span class="text-rust">Claw Patrol enforces them.</span>
            </h3>
            <p class="text-base  text-text-muted mb-5 max-w-xl">
              Every outbound request — HTTP, SQL, SSH, Kubernetes — runs through
              a rule engine before it leaves your machine. Match on method,
              host, SQL verbs and tables, k8s namespaces, plugin- defined
              facets. Decide what happens next.
            </p>
            <p class="text-base  text-text-muted max-w-xl">
              Edits are hot. Save a rule in the dashboard, the next request sees
              it. No restarts, no redeploys, no waiting.
            </p>
          </div>
          <RuleCodeBlock />
        </div>
      </div>
    </section>
  );
}
