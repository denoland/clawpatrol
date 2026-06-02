import { Button } from "../components/Button";
import { SectionLabel } from "../components/SectionLabel";

// Public dashboard walkthrough at demo.clawpatrol.dev — a simulated
// fleet with canned traffic operators can click through without
// installing anything. This section sends people straight there
// instead of trying to reproduce the UI inline.

const DEMO_URL = "https://demo.clawpatrol.dev/";

export function DemoSection() {
  return (
    <section class="pt-20 pb-16 sm:pt-32 sm:pb-28">
      <div class="max-w-5xl mx-auto px-6 sm:px-8">
        <SectionLabel>Take a tour</SectionLabel>
        <h3 class="text-3xl sm:text-4xl lg:text-5xl font-display text-center text-balance">
          Click around the admin dashboard.
        </h3>
        <p class="text-center max-w-2xl mx-auto mb-12 mt-4 text-text-muted">
          A walkthrough of the operator UI at{" "}
          <a href={DEMO_URL} class="text-rust font-semibold hover:underline">
            demo.clawpatrol.dev
          </a>
          . Drill into any request to see what the gateway captured.
        </p>
      </div>

      <div class="max-w-4xl mx-auto px-6 sm:px-8 mb-8">
        <iframe
          src="https://demo.clawpatrol.dev/"
          className="h-128 w-full border-3 border-t-24 border-navy squircle-lg shadow-[4px_6px_0_0_var(--color-canvas-300)] border-navy"
          width="100%"
        ></iframe>
      </div>

      <div class="text-center">
        <Button href={DEMO_URL} size="md">
          Open the demo
        </Button>
      </div>
    </section>
  );
}
