import { SectionLabel } from "../components/SectionLabel";

/* ──────────────────────────────────────────────────────────────────────
   Deploy — three real CLI invocations that map to the three deployment
   shapes operators ask about: wrap one agent, route a whole machine,
   or run the gateway itself.
   ──────────────────────────────────────────────────────────────────── */

const MODES: { title: string; command: string; body: string }[] = [
  {
    title: "Single process",
    command: "$ clawpatrol run claude",
    body:
      "Wrap a single command along with all its subprocesses. On " +
      "Linux a network namespace is created that intercepts and " +
      "forwards all of its traffic over WireGuard.",
  },
  {
    title: "Whole machine",
    command: "$ clawpatrol join https://gw.example.com \\\n    --whole-machine",
    body:
      "Bring up a WireGuard tunnel; every outbound packet from the " +
      "host routes through the gateway. Or run `clawpatrol login` " +
      "to join over Tailscale instead.",
  },
  {
    title: "Run the gateway",
    command: "$ clawpatrol gateway config.hcl",
    body:
      "The proxy itself. A single binary that loads your HCL config " +
      "and accepts clients tunneling in via WireGuard or Tailscale.",
  },
];

function Terminal({ source }: { source: string }) {
  return (
    <pre
      class="text-[13px] font-mono leading-relaxed
        bg-navy text-canvas/85 squircle-md px-4 py-3
        overflow-x-auto border border-navy-700 whitespace-pre"
    >
      <code>{source}</code>
    </pre>
  );
}

export function DeploySection() {
  return (
    <section class="bg-canvas-muted py-24 sm:py-32">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <SectionLabel>Run it</SectionLabel>
        <div class="max-w-3xl mx-auto text-center mb-12 sm:mb-16">
          <h3 class="text-3xl sm:text-4xl lg:text-5xl font-display font-bold text-balance mb-5 text-text">
            Wrap one agent{" "}
            <span class="text-rust">or a whole machine.</span>
          </h3>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {MODES.map((m) => (
            <div
              key={m.title}
              class="bg-canvas border border-navy-200 squircle-md
                p-6 flex flex-col gap-4"
            >
              <h4 class="text-xl font-display font-bold text-text">
                {m.title}
              </h4>
              <Terminal source={m.command} />
              <p class="text-sm text-text-muted">{m.body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
