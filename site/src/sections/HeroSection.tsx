import { InstallTerminal } from "../components/InstallTerminal";
import { IsometricStack } from "../components/IsometricStack";

// Single source of truth for the hero H1 and the page <title>.
// vite.config.ts uses SITE_TITLE in a transformIndexHtml hook, and
// docs-render.ts uses SITE_TITLE for prerender meta tags. Change
// here and all three surfaces stay in lockstep.
export const HERO_H1 = "The security firewall for agents";
export const SITE_TITLE = `Claw Patrol - ${HERO_H1}`;

export function HeroSection() {
  return (
    <section class="max-w-6xl mx-auto px-6 sm:px-8
      pt-16 sm:pt-28 pb-16">
      <div class="grid md:grid-cols-2 gap-12 md:gap-12 lg:gap-16 items-center w-full">
        <div class="order-2 md:order-1 min-w-0 flex flex-col items-center md:items-start text-center md:text-left">
          <h1 class="text-4xl sm:text-5xl md:text-5xl lg:text-6xl lg:text-[4rem] mb-6 font-display text-balance text-text">
            {HERO_H1}
          </h1>
          <p class="text-sm mb-6 max-w-2xl font-sans font-bold uppercase text-text text-balance">
            Give agents power. Don't give up control.
          </p>
          <p class="mb-10 max-w-2xl text-text-muted text-pretty">
            Claw Patrol holds agent credentials, parses their traffic at the
            wire, and gates actions with rules you write, all while keeping an
            audit log of everything that happens.
          </p>
          <InstallTerminal />
        </div>
        <div class="order-1 md:order-2 flex justify-center">
          <IsometricStack class="w-40 sm:w-48 md:w-full md:max-w-56 lg:max-w-64" />
        </div>
      </div>
    </section>
  );
}
