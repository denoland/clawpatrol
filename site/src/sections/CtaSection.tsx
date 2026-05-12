import { Button } from "../components/Button";
import { InstallTerminal } from "../components/InstallTerminal";
import { SectionLabel } from "../components/SectionLabel";

export function CtaSection() {
  return (
    <section
      class="max-w-5xl mx-auto px-6 sm:px-8
      pt-20 sm:pt-32 pb-20 sm:pb-32 text-center"
    >
      <SectionLabel>Open source</SectionLabel>
      <p
        class="max-w-lg mx-auto text-base sm:text-lg
         mb-10 text-text-muted"
      >
        The proxy handles your secrets — it must be auditable. MIT licensed.
        Multiple agents share secrets and endpoints, each with their own
        policies.
      </p>
      <img
        src="/clawpatrol.png"
        alt="Claw Patrol mascot"
        class="w-72 md:w-96 max-w-full mx-auto mb-10
          mix-blend-multiply"
      />
      <div class="mb-12 flex justify-center">
        <InstallTerminal variant="expanded" />
      </div>
      <Button href="https://github.com/denoland/clawpatrol" size="lg">
        Get Started
      </Button>
    </section>
  );
}
