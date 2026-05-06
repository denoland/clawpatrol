import { Button } from "../components/Button";

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
            class="text-3xl sm:text-4xl md:text-[3.5rem]
              font-black tracking-tight
              leading-[1.1] mb-8 font-display
              text-text"
          >
            The security proxy
            <br />
            for AI agents
          </h1>
          <p
            class="text-lg leading-relaxed mb-10 max-w-lg
            text-text-muted"
          >
            Decide what your agents can do — before they do it. Claw Patrol is
            a forward proxy that intercepts every outbound request, runs it
            against rules you write, and routes the risky ones to a human or
            an LLM judge for approval. Secrets stay out of the agent. Every
            decision is logged. Works with Claude Code, Codex, or any agent —
            no code changes.
          </p>
          <Button href="https://github.com/denoland/clawpatrol" size="lg">
            Get Started
          </Button>
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

      <p
        class="text-sm mt-24 text-center text-text-muted
        font-sans"
      >
        Built by{" "}
        <a
          href="https://deno.com"
          class="underline underline-offset-2
            transition-colors text-text"
        >
          Deno
        </a>
      </p>
    </section>
  );
}
