export function HeroSection() {
  return (
    <section class="max-w-6xl mx-auto px-6 sm:px-8
      pt-16 sm:pt-28 pb-16">
      <div class="grid md:grid-cols-2 gap-10
        md:gap-16 items-center">
        <div>
          <h1
            class="text-3xl sm:text-4xl md:text-[3.5rem]
              font-normal tracking-tight
              leading-[1.1] mb-8 font-display
              text-console-dark"
          >
            The security proxy
            <br />
            for AI agents
          </h1>
          <p class="text-lg leading-relaxed mb-10 max-w-lg
            text-text-muted">
            Your agent can access every API key in
            plaintext — and you have no idea what it costs
            or where requests go. Claw Patrol is a forward
            proxy that intercepts all traffic, injects
            secrets without exposing them, and shows you
            everything. Works with OpenAI, Claude Code,
            Codex, or any agent — no code changes.
          </p>
          <a
            href="https://github.com/denoland/clawpatrol-go"
            class="px-7 py-3.5 text-sm uppercase
              tracking-wider font-semibold
              transition-colors squircle-full neu-raised
              [--neu-face:var(--color-accent)]
              [--face-highlight-opacity:50%]
              bg-accent text-console-dark font-display
              isolate hover:bg-accent-light"
          >
            Get Started
          </a>
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

      <p class="text-sm mt-24 text-center text-text-muted
        font-sans">
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
