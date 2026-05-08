import { Button } from "../components/Button";
import { InstallTerminal } from "../components/InstallTerminal";

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
        <div>
          <h1
            class="text-3xl sm:text-4xl md:text-5xl md:text-[3.5rem]
              font-bold
               mb-8 font-display text-balance
              text-text"
          >
            Let your agents into production.
          </h1>
          <p
            class="mb-10 max-w-lg
            text-text-muted"
          >
            An agent stuck in a sandbox is a toy. Handing it your prod keys is
            reckless. Claw Patrol sits at the only universal checkpoint — the
            network — between your agents and real systems. Every outbound
            action runs against rules you write in HCL. Risky ones get a human
            in Slack or an LLM judge. Secrets live in the proxy, not the agent.
            Works with Claude Code, Codex, or any agent — no code changes.
          </p>
          <Button href="https://github.com/denoland/clawpatrol" size="lg">
            Get Started
          </Button>
          <div class="mt-5 max-w-lg">
            <InstallTerminal />
          </div>
        </div>

        <div class="flex justify-center">
          <img
            src="/clawpatrol.png"
            alt="Claw Patrol mascot"
            class="w-72 md:w-96 max-w-full
              mix-blend-multiply"
          />
        </div>
      </div>
    </section>
  );
}
