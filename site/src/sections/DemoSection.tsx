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
          <a
            href={DEMO_URL}
            class="text-rust font-semibold hover:underline"
          >
            demo.clawpatrol.dev
          </a>. Drill into any request to see what the gateway captured.
        </p>
      </div>

      <div class="max-w-4xl mx-auto px-6 sm:px-8 mb-12">
        <a href={DEMO_URL} class="block group">
          <img
            src="/screenshots/demo-dashboard.png"
            alt="Claw Patrol admin dashboard showing a device fleet and live request feed"
            class="w-full block border border-navy
              transition-opacity group-hover:opacity-90"
          />
        </a>
      </div>

      <div class="text-center">
        <Button href={DEMO_URL} size="lg">
          Open the demo
        </Button>
      </div>
    </section>
  );
}
