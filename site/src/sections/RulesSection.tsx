import { HclCode } from "../components/HclCode";
import { SectionLabel } from "../components/SectionLabel";
import { TerminalFrame } from "../components/TerminalFrame";
import { snippet } from "../lib/example";
import { protocol_https, protocol_k8s, protocol_sql } from "../lib/examples";

const PROTOCOLS: {
  name: string;
  body: string;
  example: string;
}[] = [
  {
    name: "HTTP",
    body:
      "Match on method, path, headers, or body, and route it through an LLM judge before it " +
      "goes out.",
    example: snippet(protocol_https),
  },
  {
    name: "SQL",
    body:
      "Postgres and ClickHouse traffic parsed verb-by-verb. Match by " +
      "SQL verb, table, function name, and substrings of the " +
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
    <section class="bg-navy-700 py-24 sm:py-32 text-canvas">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <SectionLabel>Rules</SectionLabel>

        <div class="max-w-3xl mx-auto text-center mb-16">
          <h3 class="text-4xl sm:text-5xl md:text-6xl font-display text-balance mb-5">
            You write access rules.{" "}
            <span class="text-rust">Claw Patrol enforces them.</span>
          </h3>
          <p class="text-base text-canvas/70 text-balance max-w-prose mx-auto">
            Every outbound request runs through{" "}
            <a href="/docs/rules/" class="underline underline-offset-2">
              Claw Patrol's rule engine
            </a>
            . Match on HTTP method, SQL verb, k8s resource, and more; not just
            URLs. Rules go live the second you press save.
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
                <h4 class="text-3xl lg:text-4xl font-display text-canvas mb-3 mt-8 lg:mt-0">
                  {p.name}
                </h4>
                <p class="text-base text-canvas/70 text-balance">{p.body}</p>
              </div>
              <TerminalFrame class="block min-w-0 p-5 sm:p-6 before:border-navy-500 after:border-navy-500 squircle-lg">
                <HclCode
                  source={p.example}
                  class="text-[13px] sm:text-sm font-mono leading-relaxed text-canvas overflow-x-auto whitespace-pre"
                />
              </TerminalFrame>
            </div>
          ))}
        </div>

        <p class="mt-14 text-sm text-canvas/70 text-center max-w-xl mx-auto">
          Extend Claw Patrol with plugins{" "}
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
