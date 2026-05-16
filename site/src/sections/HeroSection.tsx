import { FlowDiagram } from "../components/FlowDiagram";
import { InstallTerminal } from "../components/InstallTerminal";
import { HERO_H1 } from "../copy";

export function HeroSection() {
  return (
    <section
      class="max-w-6xl mx-auto px-6 sm:px-8
      pt-16 sm:pt-28 pb-16"
    >
      <div
        class="grid md:grid-cols-2 gap-10
        md:gap-16 items-center"
      >
        <div class="min-w-0">
          <h1
            class="text-4xl sm:text-5xl md:text-6xl md:text-[4rem]
              font-bold
               mb-4 font-display text-balance
              text-text"
          >
            {HERO_H1}
          </h1>
          <p
            class="text-xl sm:text-2xl mb-4 max-w-lg font-display
            font-semibold text-text text-balance"
          >
            Sleep easy while your agents have access to prod.
          </p>
          <p
            class="mb-10 max-w-lg
            text-text-muted"
          >
            Claw Patrol holds your credentials, parses every protocol at the wire, and gates each
            action with rules you write. Block <code>DROP TABLE</code>. Gate{" "}
            <code>kubectl delete pod</code>. Send POSTs to GitHub through an LLM judge.
          </p>
          <InstallTerminal />
        </div>

        <div class="flex justify-center min-w-0">
          <FlowDiagram />
        </div>
      </div>
    </section>
  );
}
