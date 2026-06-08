import { Button } from "../components/Button";
import { InstallTerminal } from "../components/InstallTerminal";

export function CtaSection() {
  return (
    <section
      class="max-w-5xl mx-auto px-6 sm:px-8
      py-32 md:py-64 text-center"
    >
      <img
        src="/claw-patrol-icon.svg"
        alt=""
        aria-hidden="true"
        class="size-24 mx-auto mb-8"
      />
      <h2 class="text-3xl sm:text-5xl mb-4 font-display">Open Source</h2>
      <p
        class="max-w-lg mx-auto text-base sm:text-lg
         mb-4 text-text-muted"
      >
        The proxy holds your secrets and watches every byte your agents send. It
        has to be auditable, so it’s{" "}
        <a
          href="https://github.com/denoland/clawpatrol/blob/main/LICENSE.md"
          class="underline underline-offset-2"
        >
          MIT licensed
        </a>
        .
      </p>
      <div class="mb-8 mt-16 flex justify-center">
        <InstallTerminal variant="expanded" />
      </div>
      <Button
        href="https://github.com/denoland/clawpatrol"
        size="md"
        target="_blank"
      >
        Get Started
      </Button>
    </section>
  );
}
