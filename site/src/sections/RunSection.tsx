import { SectionLabel } from "../components/SectionLabel";
import { TerminalFrame } from "../components/TerminalFrame";

// Run — the happy path, top to bottom. Deployment variants
// (--whole-machine, per-process via netns, Tailscale join, the
// gateway side) live in the docs; this section just shows what a
// first-time visitor types.

const SESSION = `# Join your device to a gateway
$ clawpatrol join https://gw.example.com

# Run your agent through it
$ clawpatrol run codex`;

export function RunSection() {
  return (
    <section class="bg-canvas-muted py-24 sm:py-32">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <SectionLabel>Run it</SectionLabel>
        <div class="max-w-3xl mx-auto text-center mb-12 sm:mb-16">
          <h3 class="text-3xl sm:text-4xl lg:text-5xl font-display text-balance mb-5 text-text">
            Connect over <span class="text-rust">WireGuard</span> or{" "}
            <span class="text-rust">Tailscale</span>.
          </h3>
          <p class="text-base text-text-muted text-balance">
            Nothing in the agent changes to use Claw Patrol.
          </p>
        </div>

        <div class="max-w-2xl mx-auto">
          <TerminalFrame class="block px-5 py-4">
            <pre class="text-sm font-mono leading-relaxed text-canvas overflow-x-auto whitespace-pre">
              <code>{SESSION}</code>
            </pre>
          </TerminalFrame>
        </div>
      </div>
    </section>
  );
}
