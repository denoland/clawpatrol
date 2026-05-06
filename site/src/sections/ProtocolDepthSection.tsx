import { SectionLabel } from "../components/SectionLabel";

/* ──────────────────────────────────────────────────────────────────────
   Multi-protocol depth — sells the idea that the proxy doesn't just
   sniff HTTP, it actually parses each protocol so rules can match on
   meaningful fields. Dark navy band — first major palette break of
   the page after the cream + canvas-muted runs.
   ──────────────────────────────────────────────────────────────────── */

const PROTOCOLS: {
  name: string;
  body: string;
  example: string;
}[] = [
  {
    name: "HTTPS",
    body:
      "Method, URL, headers, body. Any host, any service. " +
      "Plugins add per-service facets — github.repo, slack.channel.",
    example: `{
  "http.method": "DELETE",
  "http.url": {
    "contains": "/repos/"
  }
}`,
  },
  {
    name: "SQL",
    body:
      "Postgres and ClickHouse traffic parsed verb-by-verb. " +
      "Match SELECT, INSERT, DROP. Inspect tables and statement text.",
    example: `{
  "sql.verb": {
    "in": ["DROP", "TRUNCATE"]
  }
}`,
  },
  {
    name: "SSH",
    body:
      "Commands sent over interactive shells and exec sessions. " +
      "Block rm -rf. Approve sudo. Audit every keystroke.",
    example: `{
  "ssh.command": {
    "contains": "rm -rf"
  }
}`,
  },
  {
    name: "Kubernetes",
    body:
      "API calls to kube-apiserver. Match by namespace, resource, " +
      "and verb — protect prod from accidental kubectl delete.",
    example: `{
  "k8s.namespace": "prod",
  "k8s.verb": "delete"
}`,
  },
  {
    name: "Plugins",
    body:
      "Write a plugin in TypeScript and emit your own facets. " +
      "Rules can match on whatever you surface.",
    example: `{
  "myplugin.action": "transfer",
  "myplugin.amount_tier": "high"
}`,
  },
];

export function ProtocolDepthSection() {
  return (
    <section class="bg-navy-600 py-24 sm:py-32 text-canvas">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <SectionLabel>Not just HTTP</SectionLabel>

        <div class="max-w-3xl mx-auto text-center mb-16">
          <h3 class="text-3xl sm:text-4xl md:text-5xl font-display font-extrabold  mb-5">
            Rules see into <span class="text-rust">every request.</span>
          </h3>
          <p class="text-base  text-canvas/70">
            Most gateways stop at HTTP method and URL. Claw Patrol parses each
            protocol — so you can write rules that mean something. Block
            destructive SQL. Gate sudo over SSH. Quarantine prod kubectl.
          </p>
        </div>

        <p class="text-xs uppercase tracking-[0.25em] font-display font-extrabold text-rust-300 mb-5 text-center">
          Match anything in the request
        </p>
        <ul class="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {PROTOCOLS.map((p) => (
            <li
              key={p.name}
              class="bg-navy squircle-lg p-6
                flex flex-col gap-4"
            >
              <h4 class="text-2xl font-display font-extrabold text-canvas">
                {p.name}
              </h4>
              <p class="text-sm  text-canvas/70">{p.body}</p>
              <pre
                class="block text-[12px] mt-4  font-mono
                  bg-navy-950 text-rust-200 px-3 py-2 rounded-sm
                  whitespace-pre-wrap break-words"
              >
                {p.example}
              </pre>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
