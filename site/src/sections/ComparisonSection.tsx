import { SectionLabel } from "../components/SectionLabel";

type Player = { name: string; url: string };
type Group = { label?: string; players: Player[] };
type Category = {
  title: string;
  groups: Group[];
  gap: string;
  note?: string;
};

const CATEGORIES: Category[] = [
  {
    title: "Watch the LLM call",
    groups: [
      {
        label: "Routing & observability",
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
            url:
              "https://cloud.google.com/security-command-center/docs/model-armor-overview",
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
    title: "Watch the tool call",
    groups: [
      {
        players: [
          { name: "Crab Trap", url: "https://github.com/brexhq/CrabTrap" },
          {
            name: "Prompt Security MCP Gateway",
            url: "https://www.prompt.security",
          },
          { name: "httpjail", url: "https://github.com/coder/httpjail" },
        ],
      },
    ],
    gap: "URLs and body bytes only. DROP TABLE and SELECT 1 look the same.",
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
        ],
      },
    ],
    gap: "Confines what the agent can touch, not whether each action makes sense.",
    note:
      "Complementary to Claw Patrol. Most agents already run in their own " +
      "VM; if yours doesn't, layer an OS sandbox underneath.",
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
      <div class="max-w-5xl mx-auto px-6 sm:px-8">
        <div class="max-w-max">
          <SectionLabel>How it compares</SectionLabel>
        </div>
        <p class="max-w-2xl mb-12 sm:mb-16 text-base text-text-muted mt-6 sm:mt-8">
          Many teams have attacked this problem, each watching a different
          boundary. Most stop at the surface. Claw Patrol watches the protocol
          underneath, where SQL verbs and k8s resources are facts your rules
          can match on.
        </p>
        <div class="grid md:grid-cols-2 gap-4 sm:gap-6">
          {CATEGORIES.map((c) => <CategoryCard key={c.title} category={c} />)}
        </div>
        <SynthesisCard />
      </div>
    </section>
  );
}

function CategoryCard({ category: c }: { category: Category }) {
  return (
    <div
      class="p-6 sm:p-8 bg-canvas squircle-md
        border border-navy-200 border-t-2 border-t-rust-300"
    >
      <h4 class="font-display font-bold text-xl mb-4 text-text">{c.title}</h4>
      <div class="space-y-3 mb-4">
        {c.groups.map((g, i) => (
          <div key={g.label ?? i}>
            {g.label && (
              <div class="text-text-subtle font-mono uppercase tracking-wider text-2xs mb-1">
                {g.label}
              </div>
            )}
            <div class="text-[15px] text-text leading-relaxed">
              {g.players.map((p, j) => (
                <span key={p.name}>
                  {j > 0 && <span class="text-text-subtle"> · </span>}
                  <a
                    href={p.url}
                    class="font-medium hover:text-rust hover:underline
                      underline-offset-2 transition-colors"
                  >
                    {p.name}
                  </a>
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
      <p class="text-text-muted text-[14px] italic border-l-2 border-rust-200 pl-3">
        {c.gap}
      </p>
      {c.note && (
        <p class="text-text text-[14px] font-medium mt-3">{c.note}</p>
      )}
    </div>
  );
}

function SynthesisCard() {
  return (
    <div
      class="mt-6 sm:mt-8 p-8 sm:p-12 squircle-md
        bg-rust-100 border-2 border-rust-300"
    >
      <div class="flex items-center gap-3 mb-4">
        <img
          src="/claw-patrol-icon.svg"
          alt=""
          class="w-10 h-10"
          aria-hidden="true"
        />
        <h4 class="font-display font-bold text-3xl sm:text-4xl text-text">
          Claw Patrol
        </h4>
      </div>
      <p class="text-text text-base sm:text-lg max-w-3xl leading-relaxed">
        Parses Postgres, Kubernetes, ClickHouse, HTTPS, and SSH at the protocol
        layer, so rules can match a SQL verb or a k8s resource directly. Holds
        the secrets, routes risky calls to a human or an LLM judge, records
        every byte. One declarative config across every service.
      </p>
    </div>
  );
}
