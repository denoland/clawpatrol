import { HclCode } from "../components/HclCode";
import { SectionLabel } from "../components/SectionLabel";
import { snippet } from "../lib/example";
import httpsSrc from "../../examples/protocol-https.hcl?raw";
import sqlSrc from "../../examples/protocol-sql.hcl?raw";
import k8sSrc from "../../examples/protocol-k8s.hcl?raw";

/* ──────────────────────────────────────────────────────────────────────
   Multi-protocol depth — sells the idea that the gateway doesn't just
   sniff HTTP, it parses each protocol (HTTP, SQL, Kubernetes) so rules
   can match on meaningful fields of every action. Dark navy band —
   first major palette break after the cream / canvas-muted runs.
   ──────────────────────────────────────────────────────────────────── */

const PROTOCOLS: {
  name: string;
  body: string;
  example: string;
}[] = [
  {
    name: "HTTPS",
    body:
      "Method, path, headers, body. Any host, any service. " +
      "Hostname matching is implicit via the endpoint scope.",
    example: snippet(httpsSrc),
  },
  {
    name: "SQL",
    body:
      "Postgres and ClickHouse traffic parsed verb-by-verb. " +
      "Match SELECT, INSERT, DROP. Inspect tables and statement text.",
    example: snippet(sqlSrc),
  },
  {
    name: "Kubernetes",
    body:
      "API calls to kube-apiserver. Match by namespace, resource, " +
      "and verb — protect prod from accidental kubectl delete.",
    example: snippet(k8sSrc),
  },
];

export function ProtocolDepthSection() {
  return (
    <section class="bg-navy-600 py-24 sm:py-32 text-canvas">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <SectionLabel>Not just HTTP</SectionLabel>

        <div class="max-w-3xl mx-auto text-center mb-16">
          <h3 class="text-4xl sm:text-5xl md:text-6xl font-display font-bold text-balance mb-5">
            Rules dive into <span class="text-rust">every action.</span>
          </h3>
          <p class="text-base  text-canvas/70">
            Most gateways stop at HTTP method and URL. Claw Patrol parses each
            protocol — so you can write rules that mean something. Block
            destructive SQL. Quarantine prod kubectl. Gate specific ssh
            commands.
          </p>
        </div>

        <p class="text-xs uppercase tracking-[0.25em] font-display font-bold text-rust-300 mb-5 text-center">
          Match anything in the action
        </p>
        <ul class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {PROTOCOLS.map((p) => (
            <li
              key={p.name}
              class="min-w-0 bg-navy squircle-lg p-6
                flex flex-col gap-4"
            >
              <h4 class="text-3xl font-display font-bold text-canvas">
                {p.name}
              </h4>
              <p class="text-sm  text-canvas/70">{p.body}</p>
              <HclCode
                source={p.example}
                class="block text-[12px] mt-2 font-mono
                  bg-navy-950 text-canvas/85 px-3 py-2 rounded-sm
                  whitespace-pre overflow-x-auto [scrollbar-width:none]"
              />
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
