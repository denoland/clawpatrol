import type { ComponentChildren } from "preact";
import { FlowDiagram } from "../components/FlowDiagram.tsx";
import { SectionLabel } from "../components/SectionLabel";

const CAPABILITIES: { heading: string; body: string }[] = [
  {
    heading: "LLM Gateways",
    body:
      "Intercept LLM calls to route between providers, manage model keys, " +
      "and log usage. Claw Patrol sees LLM traffic too, but its focus is " +
      "the actions the agent takes against your services. A plugin can add " +
      "gateway features.",
  },
  {
    heading: "Content Guardrails",
    body:
      "Scan LLM messages for unsafe content. Claw Patrol focuses on the " +
      "services the agent reaches, not the model output. A plugin can add " +
      "content scanning.",
  },
  {
    heading: "HTTP and MCP Gateways",
    body:
      "HTTP proxies that apply policies and hold credentials. Claw Patrol " +
      "does the same and also speaks non-HTTP wire protocols like Postgres.",
  },
  {
    heading: "Sandboxes",
    body:
      "Confine what the agent does on its computer. Claw Patrol doesn't " +
      "sandbox; it intercepts the network instead. Agents already running " +
      "in a dedicated VM still need rules on which services they reach. " +
      "Stack the two.",
  },
  {
    heading: "Credential Stores",
    body:
      "Hold credentials so the agent never sees the real secret. Claw " +
      "Patrol does the same, paired with wire-level rules on every call " +
      "those credentials authorize.",
  },
];

export function ComparisonSection() {
  return (
    <section class="py-24 sm:py-32">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <SectionLabel class="ml-0 mb-4!">Comparison</SectionLabel>
        <h3 class="text-3xl sm:text-5xl font-display mb-3">
          Where Claw Patrol stands
        </h3>
        <p class="text-text-muted text-base sm:text-lg max-w-2xl mb-16">
          Many security tools touch agents. The differences matter.
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
