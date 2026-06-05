import type { ComponentChildren } from "preact";
import { FlowDiagram } from "../components/FlowDiagram.tsx";
import { SectionLabel } from "../components/SectionLabel";

const CAPABILITIES: { heading: string; body: string }[] = [
  {
    heading: "Watches tool calls at the protocol layer",
    body:
      "Postgres, Kubernetes, HTTPS — with a plugin API for the rest. " +
      "Rules match SQL verbs and k8s resources directly, not just URLs.",
  },
  {
    heading: "Routes risky calls for approval",
    body:
      "A human or an LLM judge gates the actions that need a second look " +
      "before the request leaves the proxy.",
  },
  {
    heading: "Safely holds the secrets",
    body:
      "Credentials live in the gateway and get stamped onto outbound " +
      "requests. A compromised agent has nothing to leak.",
  },
  {
    heading: "Records every byte",
    body:
      "Every request and response, across every system, in one audit " +
      'stream. "What just happened?" has one place to look.',
  },
];

export function ComparisonSection() {
  return (
    <section class="py-24 sm:py-32">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <SectionLabel class="ml-0 mb-4!">Comparison</SectionLabel>
        <h3 class="text-3xl sm:text-5xl font-display mb-3">
          One LLM gateway to control everything
        </h3>
        <p class="text-text-muted text-base sm:text-lg max-w-2xl mb-16">
          Other tools cover one piece. Claw Patrol watches, gates, holds, and
          audits, all at the same wire.
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
      <CheckIcon />
      <div>
        <h4 class="text-xl sm:text-2xl font-display text-text leading-tight">
          {heading}
        </h4>
        <p class="mt-2 text-text-muted leading-snug">{children}</p>
      </div>
    </li>
  );
}

// Small check glyph — just the checkmark stroke, no surrounding box,
// sized to sit alongside text-base body copy without crowding it.
function CheckIcon() {
  return (
    <svg
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2.5"
      stroke-linecap="round"
      stroke-linejoin="round"
      class="shrink-0 mt-1.5 text-navy"
      aria-hidden="true"
    >
      <path d="m5 12 5 5 9-11" />
    </svg>
  );
}
