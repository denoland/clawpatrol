import type { ComponentChildren, JSX } from "preact";
import { FlowDiagram } from "../components/FlowDiagram.tsx";
import { SectionLabel } from "../components/SectionLabel";

type IconKey = "llm" | "guardrail" | "gateway" | "sandbox" | "credentials";

const CAPABILITIES: { heading: string; body: string; icon: IconKey }[] = [
  {
    heading: "LLM Gateways",
    icon: "llm",
    body:
      "Route LLM calls between providers and log usage. Claw Patrol watches " +
      "LLM traffic too, but focuses on what agents do downstream.",
  },
  {
    heading: "Content Guardrails",
    icon: "guardrail",
    body: "Scan model output for unsafe content. Claw Patrol scans actions, not just words.",
  },
  {
    heading: "HTTP and MCP Gateways",
    icon: "gateway",
    body:
      "HTTP proxies that hold credentials and apply policies. Claw Patrol " +
      "does the same, plus non-HTTP protocols like Postgres.",
  },
  {
    heading: "Sandboxes",
    icon: "sandbox",
    body:
      "Confine what an agent does on its machine. Claw Patrol limits what " +
      "it can reach instead — stack the two.",
  },
  {
    heading: "Credential Stores",
    icon: "credentials",
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
          Lots of tools exist in the agent space, solving individual problems.
          Claw Patrol takes a holistic approach.
        </p>

        <div class="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-12 md:gap-16">
          <ul class="space-y-8 max-w-xl">
            {CAPABILITIES.map((c) => (
              <Capability
                key={c.heading}
                heading={c.heading}
                icon={c.icon}
              >
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
  icon,
  children,
}: {
  heading: string;
  icon: IconKey;
  children: ComponentChildren;
}) {
  return (
    <li class="flex items-start gap-3">
      <CapabilityIcon icon={icon} />
      <div>
        <h4 class="text-xl sm:text-2xl font-display text-text leading-tight">
          {heading}
        </h4>
        <p class="mt-2 text-text-muted leading-snug">{children}</p>
      </div>
    </li>
  );
}

// Each icon ties to the tool category: sparkle for LLM (AI), shield
// for content guardrails (filter), globe for HTTP/MCP gateways
// (network), 3D cube for sandboxes (confined space), key for
// credential stores.
const ICON_PATHS: Record<IconKey, JSX.Element> = {
  llm: (
    <>
      <line x1="9" y1="3" x2="9" y2="21" />
      <line x1="3" y1="12" x2="21" y2="12" />
      <path d="M 16 7 L 21 12 L 16 17" />
    </>
  ),
  guardrail: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <line x1="7" y1="12" x2="17" y2="12" />
    </>
  ),
  gateway: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <line x1="3.5" y1="12" x2="20.5" y2="12" />
      <ellipse cx="12" cy="12" rx="4" ry="8.5" />
    </>
  ),
  sandbox: (
    <>
      <path d="M 4 8 L 12 4 L 20 8 L 12 12 Z" />
      <path d="M 4 8 V 17 L 12 21 V 12" />
      <path d="M 20 8 V 17 L 12 21" />
    </>
  ),
  credentials: (
    <>
      <circle cx="8" cy="16" r="3" />
      <line x1="10" y1="14" x2="20" y2="4" />
      <line x1="18" y1="6" x2="21" y2="9" />
      <line x1="15" y1="9" x2="18" y2="12" />
    </>
  ),
};

function CapabilityIcon({ icon }: { icon: IconKey }) {
  return (
    <svg
      width="20"
      height="20"
      viewBox="0 0 24 24"
      class="shrink-0 mt-1.5 text-navy"
      fill="none"
      stroke="currentColor"
      stroke-width="1.75"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      {ICON_PATHS[icon]}
    </svg>
  );
}
