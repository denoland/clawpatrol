import type { ComponentChildren } from "preact";
import { FlowDiagram } from "../components/FlowDiagram.tsx";
import { SectionLabel } from "../components/SectionLabel";

const CAPABILITIES: { heading: string; body: string }[] = [
  {
    heading: "LLM Gateways",
    body:
      "Route LLM calls between providers and log usage. Claw Patrol watches " +
      "LLM traffic too, but focuses on what agents do downstream.",
  },
  {
    heading: "Content Guardrails",
    body: "Scan model output for unsafe content. Claw Patrol scans actions, not words.",
  },
  {
    heading: "HTTP and MCP Gateways",
    body:
      "HTTP proxies that hold credentials and apply policies. Claw Patrol " +
      "does the same, plus non-HTTP protocols like Postgres.",
  },
  {
    heading: "Sandboxes",
    body:
      "Confine what an agent does on its machine. Claw Patrol limits what " +
      "it can reach instead — stack the two.",
  },
  {
    heading: "Credential Stores",
    body:
      "Hold secrets so the agent never sees them. Claw Patrol does that, " +
      "paired with wire-level rules on every call those credentials authorize.",
  },
];

export function ComparisonSection() {
  return (
    <section class="py-24 sm:py-32">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <SectionLabel class="ml-0 mb-4!">Comparison</SectionLabel>
        <h3 class="text-3xl sm:text-5xl font-display mb-3">
          Built for <span class="text-rust">everything agents do</span>
        </h3>
        <p class="text-text-muted text-base sm:text-lg max-w-2xl mb-16">
          Adjacent tools overlap. Here's where the lines are.
        </p>

        <div class="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-12 md:gap-16">
          <ul class="space-y-8 max-w-xl">
            {CAPABILITIES.map((c) => (
              <Capability key={c.heading} heading={c.heading}>
                {c.body}
              </Capability>
            ))}
          </ul>
          <FlowDiagram />
        </div>
      </div>
    </section>
  );
}

function Capability({
  heading,
  children,
}: {
  heading: string;
  children: ComponentChildren;
}) {
  return (
    <li class="flex items-start gap-3">
      <DotIcon />
      <div>
        <h4 class="text-xl sm:text-2xl font-display text-text leading-tight">
          {heading}
        </h4>
        <p class="mt-2 text-text-muted leading-snug">{children}</p>
      </div>
    </li>
  );
}

function DotIcon() {
  return (
    <svg
      width="20"
      height="20"
      viewBox="0 0 24 24"
      class="shrink-0 mt-2 text-navy"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="4" fill="currentColor" />
    </svg>
  );
}
