import { SectionLabel } from "../components/SectionLabel";

export function ProblemSection() {
  return (
    <section class="max-w-5xl mx-auto px-6 sm:px-8 pt-20 pb-16 sm:pt-32 sm:pb-28 border-t border-navy-200/50">
      <SectionLabel>The problem</SectionLabel>
      <div class="max-w-3xl mx-auto">
        <h3 class="text-3xl sm:text-4xl lg:text-5xl font-display font-bold text-console-dark text-center text-balance mb-8">
          You can't control what the agent thinks. Only what it does.
        </h3>
        <p class="text-base text-text-muted text-center max-w-2xl mx-auto">
          Tool outputs, fetched web pages, files the agent reads: any can hide instructions the
          model will follow. Every credential in the agent's env is one you've given away. Gate the
          requests. Hold the secrets. Stop trying to fix the thoughts.
        </p>
      </div>
    </section>
  );
}
