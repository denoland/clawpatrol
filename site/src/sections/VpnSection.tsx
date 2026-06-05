// Sits right under the hero. The pitch: wrapping an agent with
// Claw Patrol takes one word — no SDK, no rewrite. Demo video is
// the visual anchor; copy and command line are deliberately
// lightweight so they don't compete with it.

export function VpnSection() {
  return (
    <section class="bg-navy-700 py-32 sm:py-44 text-canvas">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <div class="grid md:grid-cols-[2fr_3fr] gap-12 md:gap-12 lg:gap-16 items-center w-full">
          <div class="min-w-0 flex flex-col items-center md:items-start text-center md:text-left">
            <h3 class="text-3xl sm:text-4xl md:text-5xl font-display text-balance mb-3 text-canvas">
              Just call <span class="text-rust">any agent</span>
            </h3>
            <p class="text-base text-canvas/70 mb-6 text-pretty">
              Prefix any agent command with{" "}
              <code class="font-mono text-canvas">clawpatrol run</code>. Same
              workflow, every action gated.
            </p>
            <div class="font-mono text-sm text-canvas/80">
              <span class="text-canvas/40">$</span> clawpatrol run codex
            </div>
          </div>
          <div class="flex justify-center md:justify-end">
            <video
              src="/video/demo2.mp4"
              autoPlay
              muted
              loop
              playsInline
              preload="auto"
              aria-label="Claw Patrol dashboard demo"
              class="block w-full max-w-xl shadow-[4px_6px_0_0_var(--color-navy-900)]"
            />
          </div>
        </div>
      </div>
    </section>
  );
}
