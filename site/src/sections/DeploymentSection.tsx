import { SectionLabel } from "../components/SectionLabel";

// Compact "tech specs" beat between the comparison and the CTA.
// Intentionally low-key — just names the deployment model and
// shows the two commands. Visual weight stays on the CTA below.

export function DeploymentSection() {
  return (
    <section class="py-16">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <div class="grid md:grid-cols-[1fr_auto] gap-8 md:gap-12 items-center">
          <div>
            <SectionLabel class="ml-0 mb-3!">Self-hosted</SectionLabel>
            <h4 class="text-xl sm:text-2xl font-display mb-3 text-text">
              Runs on WireGuard or Tailscale
            </h4>
            <div class="flex items-center gap-5 text-text-muted text-sm">
              <a
                href="https://www.wireguard.com/"
                class="flex items-center gap-2 hover:text-rust"
              >
                <img
                  src="/icons/wireguard.svg"
                  alt=""
                  class="w-4 h-4 opacity-70"
                  aria-hidden="true"
                />
                WireGuard
              </a>
              <a
                href="https://tailscale.com/"
                class="flex items-center gap-2 hover:text-rust"
              >
                <img
                  src="/icons/tailscale.svg"
                  alt=""
                  class="w-4 h-4 opacity-70"
                  aria-hidden="true"
                />
                Tailscale
              </a>
            </div>
          </div>
          <div class="font-mono text-sm text-text-muted leading-relaxed">
            <div>
              <span class="text-text-subtle">$</span>{" "}
              clawpatrol join https://gw.example.com
            </div>
            <div>
              <span class="text-text-subtle">$</span> clawpatrol run codex
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
