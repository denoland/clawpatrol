import { SectionLabel } from "../components/SectionLabel";

const CHECK = (
  <span className="mx-auto flex items-center justify-center text-center w-6 h-4.5 p-1.5 rounded-[100%] squircle-xl bg-green-med align-[-0.08em]">
    <svg
      viewBox="0 0 24 24"
      class=" text-cream w-full h-auto"
      fill="none"
      stroke="currentColor"
      stroke-width="3"
      stroke-linecap="square"
      stroke-linejoin="miter"
      aria-hidden="true"
    >
      <path d="M4 12.5 L10 18.5 L20 6.5" />
    </svg>
  </span>
);
const CROSS = <span class="text-lg text-text-muted/50">&#10005;</span>;

function slug(text: string): string {
  return text.toLowerCase()
    .replace(/[^\w\s-]/g, "")
    .replace(/\s+/g, "-");
}

const FEATURES = [
  "Secret injection",
  "All outbound traffic",
  "Deep packet inspection",
  "Understands LLM traffic",
  "Rules",
  "Analytics",
] as const;

const ROWS: {
  name: string;
  desc: string;
  url: string;
  checks: boolean[];
  highlight?: boolean;
}[] = [
  { name: "Helicone", desc: "AI gateway and observability", url: "https://helicone.ai", checks: [false, false, false, true, false, true] },
  { name: "Portkey", desc: "AI gateway, guardrails, observability", url: "https://portkey.ai", checks: [false, false, false, true, true, true] },
  { name: "LiteLLM", desc: "Unified API for 100+ LLMs", url: "https://github.com/BerriAI/litellm", checks: [false, false, false, true, true, true] },
  { name: "agentgateway", desc: "Agentic proxy for AI and MCP", url: "https://github.com/agentgateway/agentgateway", checks: [false, false, false, true, true, true] },
  { name: "Clawvisor", desc: "API gateway for agent authorization", url: "https://github.com/clawvisor/clawvisor", checks: [true, false, false, false, true, true] },
  { name: "httpjail", desc: "HTTP request filter and sandbox", url: "https://github.com/coder/httpjail", checks: [false, false, false, false, true, false] },
  { name: "Agent Vault", desc: "Credential proxy and vault", url: "https://github.com/Infisical/agent-vault", checks: [true, false, false, false, true, true] },
  { name: "Crab Trap", desc: "LLM-as-judge agent proxy", url: "https://github.com/brexhq/CrabTrap", checks: [false, false, false, false, true, true] },
  { name: "Claw Patrol", desc: "Security proxy for AI agents", url: "https://github.com/denoland/clawpatrol", checks: [true, true, true, true, true, true], highlight: true },
];

export function ComparisonSection() {
  return (
    <section class="max-w-5xl mx-auto px-8 pt-8 pb-28 border-t border-green-light/50">
      <div class="pt-28" />
      <div class="max-w-max">
        <SectionLabel>How it compares</SectionLabel>
      </div>
      <h3 class="text-3xl lg:text-4xl font-display ">
        More than a gateway, more than a sandbox
      </h3>
      <p class=" max-w-2xl mb-16 text-base leading-relaxed text-text-muted mt-8">
        Many teams have attacked this problem — credential
        vaults, LLM gateways, sandboxes — but most stop at
        the surface. Hiding a key isn't enough if the agent
        can still DROP TABLE or exfiltrate data through an
        allowed API. Real security means deep inspection:
        constraining which SQL queries run, which endpoints
        get called, what payloads look like. Claw Patrol goes
        that deep.
      </p>
      <div class="overflow-x-auto">
        <table class="w-full text-sm font-sans">
          <thead>
            <tr class="border-b-2 border-green-light">
              <th class="text-left py-3 pr-4 font-medium font-display text-text-muted" />
              {FEATURES.map((f) => (
                <th
                  key={f}
                  class="py-3 px-3 font-medium
                    font-display text-text-muted
                    text-[11px] uppercase tracking-widest"
                >
                  {f}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {ROWS.map((row) => (
              <tr
                key={row.name}
                class={`border-b border-green-light/50 ${
                  row.highlight ? "bg-accent/20" : ""
                }`}
              >
                <td
                  class={`py-3 px-4 font-medium font-display
                    whitespace-nowrap ${
                    row.highlight ? "text-text" : "text-text-muted"
                  }`}
                >
                  <a
                    href={row.url}
                    class="underline underline-offset-4
                      hover:text-text transition-colors"
                  >
                    {row.name}
                  </a>
                  <span class="hidden sm:inline text-[11px]
                    font-sans font-normal text-text-muted
                    ml-1.5">
                    {row.desc}
                  </span>
                </td>
                {row.checks.map((ok, i) => {
                  const anchor = slug(
                    `${row.name} ${FEATURES[i]} ${ok}`,
                  );
                  return (
                    <td key={i} class="py-3 px-3 text-center text-lg">
                      <a href={`/docs/competitors/#${anchor}`}>
                        {ok ? CHECK : CROSS}
                      </a>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
