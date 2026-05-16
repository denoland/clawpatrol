import { SectionLabel } from "../components/SectionLabel";

type Player = { name: string; url: string };
type Group = { label?: string; players: Player[] };
type Category = {
  title: string;
  body: string;
  note?: string;
  groups: Group[];
};

const CATEGORIES: Category[] = [
  {
    title: "Watch the LLM call",
    body:
      "Sit between the agent and the model. Some focus on routing " +
      "and observability: picking the cheapest provider, retrying " +
      "on failure, tracking tokens. Others focus on content: " +
      "scanning prompts and responses for injection or PII. Both " +
      "lenses watch the conversation itself; what the agent does " +
      "after the LLM replies lives outside their view.",
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
  },
  {
    title: "Watch the tool call",
    body:
      "Sit between the agent and the world, inspecting outbound " +
      "HTTP. They use static rules, JavaScript expressions, or an " +
      "LLM judge. All see the same surface: URL, method, and " +
      "request body. The body is opaque, so a Postgres DROP TABLE " +
      "and a SELECT 1 reach them as the same shape of HTTPS call.",
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
  },
  {
    title: "Sandbox the process",
    body:
      "Run the agent inside a container or microVM with policies " +
      "on filesystem, syscalls, and egress. Useful for limiting " +
      "blast radius if the agent process is compromised or strays. " +
      "They constrain what the agent can touch, not whether each " +
      "action makes sense for the task.",
    note:
      "Complementary to Claw Patrol. Most agents already run on " +
      "their own VM; if yours doesn't, an OS sandbox is a sensible " +
      "layer underneath.",
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
  },
  {
    title: "Hold the keys",
    body:
      "Store credentials outside the agent and attach them at " +
      "request time. The agent never sees a real key, which limits " +
      "damage from a compromised process or a leaked log. The " +
      "request content itself passes through: whatever the agent " +
      "asks for after authentication, it gets.",
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
  },
];

export function ComparisonSection() {
  return (
    <section class="max-w-5xl mx-auto px-6 sm:px-8 pt-8 pb-20 sm:pb-28 border-t border-navy-200/50">
      <div class="pt-16 sm:pt-28" />
      <div class="max-w-max">
        <SectionLabel>How it compares</SectionLabel>
      </div>
      <h3 class="text-3xl sm:text-4xl lg:text-5xl font-display font-bold text-balance">
        Most tools watch one boundary.
      </h3>
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
    </section>
  );
}

function CategoryCard({ category: c }: { category: Category }) {
  return (
    <div class="p-6 sm:p-8 bg-canvas-light border border-navy-200 squircle-md">
      <h4 class="font-display font-bold text-xl mb-3 text-text">{c.title}</h4>
      <p class="text-text-muted text-[15px] mb-4">{c.body}</p>
      {c.note && (
        <p class="text-text-subtle text-[14px] italic mb-4">{c.note}</p>
      )}
      <div class="space-y-3">
        {c.groups.map((g, i) => (
          <div key={g.label ?? i}>
            {g.label && (
              <div class="text-text-subtle font-mono uppercase tracking-wider text-2xs mb-1">
                {g.label}
              </div>
            )}
            <div class="text-[14px] text-text-muted">
              {g.players.map((p, j) => (
                <span key={p.name}>
                  {j > 0 && <span class="text-text-subtle"> · </span>}
                  <a
                    href={p.url}
                    class="underline underline-offset-2 hover:text-rust"
                  >
                    {p.name}
                  </a>
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SynthesisCard() {
  return (
    <div
      class="mt-6 sm:mt-8 p-6 sm:p-10 squircle-md
        bg-rust/10 border-2 border-rust/40"
    >
      <h4 class="font-display font-bold text-2xl sm:text-3xl mb-4 text-text">
        Claw Patrol
      </h4>
      <p class="text-text text-base sm:text-lg max-w-3xl">
        Sees what the others don't. Parses Postgres, Kubernetes, ClickHouse,
        HTTPS, and SSH at the protocol layer, so rules can match a SQL verb
        or a k8s resource directly. Holds the secrets and injects them at
        request time. Routes risky calls to a human or an LLM judge.
        Records every byte. One declarative config across every service.
      </p>
    </div>
  );
}
