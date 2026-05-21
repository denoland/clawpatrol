import { Fragment } from "preact";
import { SectionLabel } from "../components/SectionLabel";

type Player = { name: string; url: string };
type Group = { label?: string; players: Player[] };
type Category = {
  title: string;
  groups: Group[];
  gap: string;
};

const CATEGORIES: Category[] = [
  {
    title: "Watch LLM calls",
    groups: [
      {
        label: "LLM Gateways",
        players: [
          { name: "Helicone", url: "https://helicone.ai" },
          { name: "Portkey", url: "https://portkey.ai" },
          { name: "LiteLLM", url: "https://github.com/BerriAI/litellm" },
          { name: "OpenRouter", url: "https://openrouter.ai" },
          {
            name: "agentgateway",
            url: "https://github.com/agentgateway/agentgateway",
          },
        ],
      },
      {
        label: "Content guardrails",
        players: [
          {
            name: "NeMo Guardrails",
            url: "https://github.com/NVIDIA/NeMo-Guardrails",
          },
          { name: "Lakera Guard", url: "https://www.lakera.ai/lakera-guard" },
          {
            name: "Google Model Armor",
            url: "https://cloud.google.com/security-command-center/docs/model-armor-overview",
          },
          {
            name: "AWS Bedrock Guardrails",
            url: "https://aws.amazon.com/bedrock/guardrails/",
          },
        ],
      },
    ],
    gap: "What the agent does after the LLM replies lives outside their view.",
  },
  {
    title: "Watch tool calls",
    groups: [
      {
        players: [
          { name: "Crab Trap", url: "https://github.com/brexhq/CrabTrap" },
          {
            name: "Prompt Security MCP Gateway",
            url: "https://www.prompt.security",
          },
          { name: "httpjail", url: "https://github.com/coder/httpjail" },
          { name: "proxyline", url: "https://proxyline.dev/" },
        ],
      },
    ],
    gap:
      "HTTP only. Non-HTTP protocols like Postgres, k8s, and SSH bypass " +
      "them entirely.",
  },
  {
    title: "Sandbox the process",
    groups: [
      {
        players: [
          {
            name: "NVIDIA OpenShell",
            url: "https://github.com/NVIDIA/OpenShell",
          },
          { name: "agentsh", url: "https://www.agentsh.org/" },
        ],
      },
    ],
    gap: "Confines what the agent can touch, not whether each action makes sense.",
  },
  {
    title: "Hold the keys",
    groups: [
      {
        players: [
          {
            name: "Agent Vault",
            url: "https://github.com/Infisical/agent-vault",
          },
          {
            name: "Clawvisor",
            url: "https://github.com/clawvisor/clawvisor",
          },
        ],
      },
    ],
    gap:
      "Secrets stay outside the agent, but the request content itself " +
      "passes through.",
  },
];

export function ComparisonSection() {
  return (
    <section class="bg-canvas-muted py-24 sm:py-32">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <SectionLabel class="ml-0 mb-4!">Comparison</SectionLabel>
        <h3 class="text-3xl sm:text-5xl font-display mb-3">
          Comprehensive capabilities
        </h3>
        <p class="text-text-muted text-base sm:text-lg max-w-2xl mb-16">
          Most tools tackle one side of the issue. Claw Patrol does it all..
        </p>

        <div class="grid grid-cols-1 md:grid-cols-[1.5fr_2fr_2.5fr] gap-x-6 gap-y-3 md:gap-y-6 items-start">
          {CATEGORIES.map((c, i) => (
            <Fragment key={c.title}>
              <div
                class={
                  "md:pr-2 pt-3 md:border-t-1.5 md:border-t-navy " +
                  (i > 0 ? "mt-6 md:mt-0" : "")
                }
              >
                <h4 class="text-xl sm:text-2xl font-display text-text leading-none">
                  {c.title}
                </h4>
                <p class="mt-2 text-text-muted text-[13px] italic leading-snug">
                  {c.gap}
                </p>
              </div>
              <CompetitorCard category={c} />
            </Fragment>
          ))}

          {/* Mobile-only synthesis heading — bridges the four
              category sections into the Claw Patrol card below. On
              md+ the grid layout makes this redundant because the
              synthesis card sits visually alongside the four rows. */}
          <div class="md:hidden mt-6 pt-3 md:border-t-1.5 md:border-navy">
            <h4 class="text-xl sm:text-2xl font-display text-text leading-none">
              All four
            </h4>
            <p class="mt-2 text-text-muted text-[13px] italic leading-snug">
              Claw Patrol covers them all.
            </p>
          </div>

          {/* Claw Patrol — last in source so mobile gets it at the
              bottom; on md+ grid placement parks it in col 3 spanning
              all four rows. `md:self-stretch` overrides the grid's
              `items-start` so this single card fills the full
              four-row height. */}
          <SynthesisColumn />
        </div>
      </div>
    </section>
  );
}

function CompetitorCard({ category: c }: { category: Category }) {
  return (
    <div class="bg-canvas-light relative p-6 flex flex-col md:self-stretch">
      <div class="absolute w-full h-full border-navy border-1.5 inset-0 z-10" />
      <div class="relative z-10 flex-1 flex items-center">
        <div class="space-y-4">
          {c.groups.map((g, i) => (
            <div key={g.label ?? i}>
              {g.label && (
                <div class="text-text-subtle font-mono uppercase tracking-wider text-2xs mb-1">
                  {g.label}
                </div>
              )}
              <ul class="text-[14px] text-text leading-relaxed space-y-1">
                {g.players.map((p) => (
                  <li
                    key={p.name}
                    class="before:content-['▪'] before:mr-1.5 before:text-text-subtle"
                  >
                    <a
                      href={p.url}
                      class="font-medium hover:text-rust hover:underline
                        underline-offset-2 transition-colors"
                    >
                      {p.name}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
      {/* horizontal-stripe drop shadow — uniform canvas color across
          all four cards now that they share one treatment. */}
      <div
        class="isolate absolute top-1.5 left-1.5 -right-2 -bottom-1.5 left-0 z-0 bg-horizontal-stripes [--color-2:transparent]"
        style="--color-1: var(--color-canvas-muted);"
      />
    </div>
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
      class="shrink-0 mt-0.5 text-navy"
      aria-hidden="true"
    >
      <path d="m5 12 5 5 9-11" />
    </svg>
  );
}

function SynthesisColumn() {
  return (
    <div class="md:col-start-3 md:row-start-1 md:row-span-4 md:self-stretch relative bg-navy-100 p-6 py-8 sm:p-8 flex flex-col items-start justify-center gap-6">
      {/* border layer (separate so it sits above the stripe shadow,
          mirroring the competitor cards' structure). */}
      <div class="absolute w-full h-full border-navy border-1.5 inset-0 z-10 pointer-events-none" />
      <img
        src="/claw-patrol-logo.svg"
        alt="Claw Patrol"
        class="h-12 w-auto relative z-10"
      />
      <ul class="text-text text-base relative z-10 space-y-3 leading-snug">
        <li class="flex items-start gap-2.5">
          <CheckIcon />
          <span>
            Watches tool calls at the protocol layer (Postgres, Kubernetes,
            HTTPS, with a plugin API for the rest), so rules match SQL verbs and
            k8s resources directly.
          </span>
        </li>
        <li class="flex items-start gap-2.5">
          <CheckIcon />
          <span>Holds the secrets.</span>
        </li>
        <li class="flex items-start gap-2.5">
          <CheckIcon />
          <span>Routes risky calls to a human or an LLM judge.</span>
        </li>
        <li class="flex items-start gap-2.5">
          <CheckIcon />
          <span>Records every byte.</span>
        </li>
      </ul>
      {/* horizontal-stripe shadow — gentler 50/100 navy pairing,
          drawn behind the border layer above. */}
      <div
        class="isolate absolute top-1.5 -right-2 -bottom-1.5 left-1.5 z-0 bg-horizontal-stripes"
        style="--color-1: var(--color-navy-50); --color-2: var(--color-navy-100);"
      />
    </div>
  );
}
