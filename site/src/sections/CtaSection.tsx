import { Button } from "../components/Button";
import { InstallTerminal } from "../components/InstallTerminal";
import { SectionLabel } from "../components/SectionLabel";

export function CtaSection() {
  return (
    <section
      class="max-w-5xl mx-auto px-6 sm:px-8
      py-32 md:py-64 text-center"
    >
      <SectionLabel class="mb-4!">MIT License</SectionLabel>
      <h3 class="text-3xl sm:text-5xl mb-4 font-display">Open Source</h3>
      <p
        class="max-w-lg mx-auto text-base sm:text-lg
         mb-10 text-text-muted"
      >
        The proxy holds your secrets and watches every byte your agents send. It
        has to be auditable, so it’s MIT licensed.
      </p>
      <div class="mb-12 mt-16 flex justify-center">
        <InstallTerminal variant="expanded" />
      </div>
      <Button href="https://github.com/denoland/clawpatrol" size="lg">
        Get Started
      </Button>
    </section>
  );
}
