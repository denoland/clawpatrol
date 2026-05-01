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

const FEATURES = [
  "Secret injection",
  "All outbound traffic",
  "Understands LLM traffic",
  "Handles webhooks",
  "Analytics",
] as const;

const ROWS: {
  name: string;
  checks: boolean[];
  highlight?: boolean;
}[] = [
  { name: "Helicone", checks: [false, false, true, false, true] },
  { name: "Portkey", checks: [false, false, true, false, true] },
  { name: "LiteLLM", checks: [false, false, true, false, true] },
  { name: "agentgateway", checks: [false, false, true, false, true] },
  { name: "Clawvisor", checks: [true, false, false, false, true] },
  { name: "httpjail", checks: [false, true, false, false, false] },
  { name: "Unclaw", checks: [true, true, true, true, true], highlight: true },
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
        AI gateways see your model calls. Sandboxes isolate your process. Unclaw
        does both — it sees every request and controls what credentials your
        agent can use.
      </p>
      <div class="overflow-x-auto">
        <table class="w-full text-sm font-sans">
          <thead>
            <tr class="border-b-2 border-green-light">
              <th class="text-left py-4 pr-6 font-medium font-display text-text-muted w-40" />
              {FEATURES.map((f) => (
                <th
                  key={f}
                  class="py-4 px-4 font-medium
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
                  class={`py-4 px-6 font-medium font-display ${
                    row.highlight ? "text-text" : "text-text-muted"
                  }`}
                >
                  {row.name}
                </td>
                {row.checks.map((ok, i) => (
                  <td key={i} class="py-4 px-4 text-center text-lg">
                    {ok ? CHECK : CROSS}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
