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
    <section
      class="py-28 text-center"
      style={{
        background:
          "linear-gradient(160deg, " +
          "var(--color-green-light) 0%, " +
          "color-mix(in srgb, var(--color-green-light), var(--color-console) 8%) 100%)",
      }}
    >
      <div class="max-w-5xl mx-auto px-8">
        <SectionLabel>Built-in plugins</SectionLabel>
        <p class="text-center max-w-2xl mx-auto mb-16  leading-relaxed text-text-muted">
          Plugins are pre-configured integrations with external services.
          Connect your agent(s) without writing the request-handling, auth, or
          secret-management code yourself.
        </p>
        <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-6 sm:gap-8 max-w-2xl mx-auto">
          {INTEGRATIONS.map(({ name, id }, i) => (
            <a
              key={id}
              href={`https://github.com/denoland/clawpatrol/tree/main/src/plugins/${id}`}
              target="_blank"
              rel="noopener noreferrer"
              class="integration-tile flex flex-col items-center aspect-square
                justify-between py-4 px-2 squircle-md
                transition-transform hover:scale-[1.03] focus-visible:scale-[1.03]
                focus-visible:outline-2 focus-visible:outline-console-dark"
              style={{
                animationRange: `cover ${10 + i * 3}% cover ${35 + i * 3}%`,
              }}
            >
              <div class="flex-1 flex items-center">
                <img
                  src={`/icons/${id}.svg`}
                  alt={name}
                  width="48"
                  height="48"
                  class="opacity-80"
                />
              </div>
              <span class="text-xs font-mono text-console-dark mt-3">
                {name}
              </span>
            </a>
          ))}
        </div>
        <p class="text-center mt-16 tracking-wider text-green-med">— OR —</p>
        <a
          href="/docs/08-plugins/"
          class="block font-normal uppercase tracking-wide font-display max-w-full
            w-max mx-auto mt-16 mb-8 text-text-muted neu-raised p-6 px-8 squircle-lg
            bg-linear-to-br from-green-light to-green
            [--neu-bg:var(--color-green-light)] [--face-highlight-opacity:70%]
            [--bg-highlight-opacity:10%] [--bg-shadow-opacity:5%] hover:bg-green-light transition-colors"
        >
          Write your own plugin in one TypeScript file{" "}
          <span class="ml-1" aria-hidden="true">
            &rarr;
          </span>
        </a>
      </div>
    </section>
  );
}
