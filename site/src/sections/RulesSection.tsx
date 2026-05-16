import { HclCode } from "../components/HclCode";
import { SectionLabel } from "../components/SectionLabel";
import { snippet } from "../lib/example";
import { protocol_https, protocol_k8s, protocol_sql } from "../lib/examples";

const PROTOCOLS: {
  name: string;
  body: string;
  example: string;
}[] = [
  {
    name: "HTTPS",
    body:
      "Method, path, headers, body. Any host, any service. Match an " +
      "HTTP request shape, route it through an LLM judge before it " +
      "goes out.",
    example: snippet(protocol_https),
  },
  {
    name: "SQL",
    body:
      "Postgres and ClickHouse traffic parsed verb-by-verb. Match by " +
      "SQL verb, table, function name, even substrings of the " +
      "statement itself.",
    example: snippet(protocol_sql),
  },
  {
    name: "Kubernetes",
    body:
      "API calls to kube-apiserver. Match by namespace, resource, " +
      "verb, and name. Catch destructive verbs on the wrong cluster, " +
      "or hand exec commands to an LLM.",
    example: snippet(protocol_k8s),
  },
];

export function RulesSection() {
  return (
    <section class="bg-navy-600 py-24 sm:py-32 text-canvas">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <SectionLabel>Approval rules</SectionLabel>

        <div class="max-w-3xl mx-auto text-center mb-16">
          <h3 class="text-4xl sm:text-5xl md:text-6xl font-display font-bold text-balance mb-5">
            You write the rules.{" "}
            <span class="text-rust">Claw Patrol enforces them.</span>
          </h3>
          <p class="text-base text-canvas/70">
            Every outbound request runs through a rule engine before it leaves
            your machine. Match on HTTP method, SQL verb, k8s resource,
            plugin-defined facets — not just URLs. Edits are hot: save a rule
            in the dashboard, the next request sees it.
          </p>
        </div>

        <p class="text-xs uppercase tracking-[0.25em] font-display font-bold text-rust-300 mb-10 text-center">
          Match anything on the wire
        </p>

        <div class="space-y-10 lg:space-y-14">
          {PROTOCOLS.map((p) => (
            <div
              key={p.name}
              class="grid grid-cols-1 lg:grid-cols-[1fr_2fr] gap-6 lg:gap-12 items-start"
            >
              <div class="min-w-0">
                <h4 class="text-3xl font-display font-bold text-canvas mb-3">
                  {p.name}
                </h4>
                <p class="text-base text-canvas/70 max-w-sm">{p.body}</p>
              </div>
              <HclCode
                source={p.example}
                class="min-w-0 text-[13px] sm:text-sm font-mono leading-relaxed
                  bg-navy-950 text-canvas/85 squircle-md p-5 sm:p-6
                  overflow-x-auto whitespace-pre border border-navy-800"
              />
            </div>
          ))}
        </div>

        <p class="mt-14 text-sm text-canvas/70 text-center max-w-xl mx-auto">
          Extend Claw Patrol with your own protocol plugins.{" "}
          <a
            href="/docs/plugins/"
            class="text-rust-300 hover:text-rust-200 underline underline-offset-4"
          >
            Read more →
          </a>
        </p>
      </div>
    </section>
  );
}
