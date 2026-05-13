import { Button } from "../components/Button";
import { SectionLabel } from "../components/SectionLabel";

const INTEGRATIONS = [
  { name: "Anthropic", id: "anthropic" },
  { name: "OpenAI", id: "openai" },
  { name: "GitHub", id: "github" },
  { name: "Slack", id: "slack" },
  { name: "Notion", id: "notion" },
  { name: "Kubernetes", id: "kubernetes" },
  { name: "ClickHouse", id: "clickhouse" },
  { name: "Grafana", id: "grafana" },
];

export function IntegrationsSection() {
  return (
    <section class="py-20 sm:py-28 text-center bg-linear-to-b from-navy-100 to-navy-50">
      <div class="max-w-5xl mx-auto px-6 sm:px-8">
        <SectionLabel>Built-in plugins</SectionLabel>
        <p class="text-center max-w-2xl mx-auto mb-16   text-text-muted">
          Plugins are pre-configured integrations with external services.
          Connect your agent(s) without writing the request-handling, auth, or
          secret-management code yourself.
        </p>
        <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-6 sm:gap-8 max-w-2xl mx-auto">
          {INTEGRATIONS.map(({ name, id }) => (
            <a
              key={id}
              href="/docs/config-reference/#endpoint-blocks"
              class="flex flex-col items-center aspect-square
                justify-between py-4 px-2 squircle-md
                transition-transform hover:scale-[1.03] focus-visible:scale-[1.03]
                focus-visible:outline-2 focus-visible:outline-console-dark"
            >
              <div class="flex-1 flex items-center">
                <img
                  src={`/icons/${id}.svg`}
                  alt={name}
                  width="48"
                  height="48"
                />
              </div>
              <span class="text-xs font-mono text-console-dark mt-3">
                {name}
              </span>
            </a>
          ))}
        </div>
        <p class="text-center mt-12 sm:mt-16 tracking-wider text-navy-500">
          — OR —
        </p>
        <div class="text-center mt-12 sm:mt-16 mb-8">
          <Button href="/docs/config-reference/#endpoint-blocks" variant="normal" size="lg">
            Explore the current Go/HCL plugin model{" "}
            <span class="ml-1" aria-hidden="true">
              &rarr;
            </span>
          </Button>
        </div>
      </div>
    </section>
  );
}
