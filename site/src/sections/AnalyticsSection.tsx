import { CrtDisplay } from "../components/CrtDisplay";
import { SectionLabel } from "../components/SectionLabel";

export function AnalyticsSection() {
  return (
    <section class="pt-20 pb-16 sm:pt-32 sm:pb-28">
      <div class="max-w-5xl mx-auto px-6 sm:px-8">
        <SectionLabel>What you've been missing</SectionLabel>
        <h3 class="text-3xl sm:text-4xl lg:text-5xl font-display font-bold text-center text-balance">
          See everything your agents do in the Claw Patrol dashboard
        </h3>
        <p
          class="text-center max-w-2xl mx-auto mb-16 mt-4
          text-text-muted"
        >
          Thousands of requests across dozens of services. Claw Patrol captures it
          all passively, with zero instrumentation.
        </p>
      </div>

      <div class="max-w-6xl mx-auto mb-16">
        <CrtDisplay title="clawpatrol.dev/analytics">
          <div id="demo-chart" class="p-4 min-h-130 text-[#b8c4be]">
            <noscript>
              <img
                src="/screenshots/analytics.png"
                alt="Claw Patrol analytics dashboard"
                class="w-full block"
              />
            </noscript>
          </div>
        </CrtDisplay>
      </div>

      <p
        class="text-xs text-center mt-6 font-mono
        text-text-muted"
      >
        ^ Real data from one agent, one day.
      </p>
    </section>
  );
}
