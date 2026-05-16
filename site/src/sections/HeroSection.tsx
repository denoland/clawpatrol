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
            Let your agents read prod. Lock down the writes.
          </h1>
          <p
            class="mb-10 max-w-lg
            text-text-muted"
          >
            Claw Patrol inspects every outbound call — SQL, the Kubernetes API, HTTP semantics.
            Reads pass through. Writes run against rules you write in HCL, with risky ones routed to
            a human in Slack. Secrets live in the proxy, not the agent.
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
