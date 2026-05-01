import { CrtDisplay } from "../components/CrtDisplay";
import { SectionLabel } from "../components/SectionLabel";

export function CtaSection() {
  return (
    <section class="max-w-5xl mx-auto px-6 sm:px-8 pt-20 sm:pt-32 pb-20 sm:pb-32 text-center">
      <SectionLabel>Open source</SectionLabel>
      <p class="max-w-lg mx-auto text-base sm:text-lg leading-relaxed mb-10 text-text-muted">
        The proxy handles your secrets — it must be auditable. MIT licensed.
        Multiple agents share secrets and endpoints, each with their own
        policies. Self-host or use unclaw.dev.
      </p>
      <div class="max-w-sm md:max-w-lg mx-auto mb-16 mt-32">
        <CrtDisplay title="terminal">
          <pre
            class="px-6 sm:px-8 pt-8 pb-32 text-sm font-mono text-crt text-left"
            style={{
              textShadow:
                "0 0 6px color-mix(in srgb, var(--color-crt) 31%, transparent), 0 0 14px color-mix(in srgb, var(--color-crt-dim) 19%, transparent)",
            }}
          >
            npm install -g unclaw
          </pre>
        </CrtDisplay>
      </div>
      {/* <div>
        <a
          href="/auth/login"
          class="inline-block px-9 py-4 text-sm
            uppercase tracking-wider font-semibold
            transition-colors squircle-full
            bg-accent text-console-dark font-display neu-raised
            [--neu-face:var(--color-accent)] [--face-highlight-opacity:50%]
            hover:bg-accent-light"
        >
          Get Started — Free
        </a>
      </div> */}
      <div class="flex flex-col sm:flex-row items-center justify-center gap-4 sm:gap-5">
        <a
          href="/auth/login"
          class="px-7 py-3.5 text-sm uppercase
            tracking-wider font-semibold
            transition-colors squircle-full neu-raised
            [--neu-face:var(--color-accent)] [--face-highlight-opacity:50%]
            bg-accent text-console-dark font-display isolate hover:bg-accent-light"
        >
          Get Started
        </a>
        <a
          href="/docs/"
          class="px-7 py-3.5 text-sm uppercase
            tracking-wider transition-colors
            squircle-full neu-raised hover:bg-cream-light
            text-text font-display font-medium"
        >
          Read the Docs
        </a>
      </div>
    </section>
  );
}
