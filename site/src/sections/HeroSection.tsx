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
    <section
      class="iso-stack-host max-w-6xl mx-auto px-6 sm:px-8
      py-16 sm:py-28"
    >
      <div class="grid md:grid-cols-2 gap-12 md:gap-12 lg:gap-16 items-center w-full">
        <div class="order-2 md:order-1 min-w-0 flex flex-col items-center md:items-start text-center md:text-left relative z-10 bg-linear-to-b from-transparent py-16 via-canvas via-35% to-canvas">
          <h1 class="text-4xl sm:text-5xl md:text-5.5xl lg:text-6xl lg:text-[4rem] mb-6 font-display text-balance text-text leading-none">
            The missing option between babysitting and{" "}
            <small style="font-size: 0.9em; font-weight: 450;">YOLO</small> mode
          </h1>
          <p class="text-sm md:text-base mb-6 max-w-2xl font-sans font-bold uppercase text-text text-balance">
            The security firewall for{" "}
            <span className="text-rust">any agent</span>
          </p>
          <p class="mb-10 max-w-2xl text-text-muted text-balance">
            Claw Patrol guards credentials, parses traffic at the wire, and
            gates actions according to rules you author—all while keeping an
            audit log of everything that happens.
          </p>
          <InstallTerminal />
        </div>
        <div class="order-1 md:order-2 flex justify-center sticky top-50 z-0">
          <IsometricStack class="h-[calc(100dvh-4rem)] w-auto md:h-auto md:w-full md:max-w-56 lg:max-w-64" />
        </div>
      </div>
    </section>
  );
}
