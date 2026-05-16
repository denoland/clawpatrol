import { FlowDiagram } from "../components/FlowDiagram";
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
        <div class="min-w-0">
          <h1
            class="text-4xl sm:text-5xl md:text-6xl md:text-[4rem]
              font-bold
               mb-8 font-display text-balance
              text-text"
          >
            Give your agents read access. Gate the writes.
          </h1>
          <p
            class="mb-10 max-w-lg
            text-text-muted"
          >
            You write the rules. Plugins parse each protocol (SQL, Kubernetes, HTTPS, SSH) so they
            can match on semantics, not URLs: block <code>DROP TABLE</code>, require human approval
            for <code>kubectl delete pod</code>, or have an LLM judge whether a{" "}
            <code>SELECT</code> leaks secrets. Secrets stay in the proxy, never the agent.
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
