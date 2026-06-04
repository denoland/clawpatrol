import { InstallTerminal } from "../components/InstallTerminal";

// Single source of truth for the hero H1 and the page <title>.
// vite.config.ts uses SITE_TITLE in a transformIndexHtml hook, and
// docs-render.ts uses SITE_TITLE for prerender meta tags. Change
// here and all three surfaces stay in lockstep.
export const HERO_H1 = "The security firewall for agents";
export const SITE_TITLE = `Claw Patrol - ${HERO_H1}`;

export function HeroSection() {
  return (
    <section
      class="max-w-6xl mx-auto px-6 sm:px-8
      pt-16 sm:pt-28 pb-16"
    >
      <div
        class="grid md:grid-cols-[5fr_7fr] gap-10
        md:gap-12 items-center"
      >
        <div class="min-w-0">
          <h1 class="text-4xl sm:text-5xl md:text-6xl md:text-[4rem] mb-6 font-display text-balance text-text">
            {HERO_H1}
          </h1>
          <p
            class="text-sm mb-6 max-w-lg font-sans
            font-bold uppercase text-text text-balance"
          >
            Give agents prod access and still sleep easy
          </p>
          <p
            class="mb-10 max-w-lg
            text-text-muted"
          >
            Claw Patrol holds agent credentials, parses their traffic at the
            wire, and gates actions they take with rules you write, all while
            keeping an audit log of every action.
          </p>
          <InstallTerminal />
        </div>

        <div class="w-full mt-16 md:mt-0 min-w-0 flex md:justify-end">
          <video
            src="/clawpatrol-demo4.mp4"
            autoPlay
            loop
            muted
            playsInline
            class="w-full md:max-w-[85%] h-auto border border-navy squircle-lg shadow-[4px_6px_0_0_var(--color-canvas-300)]"
            aria-label="Claw Patrol demo screencast"
          />
        </div>
      </div>
    </section>
  );
}
