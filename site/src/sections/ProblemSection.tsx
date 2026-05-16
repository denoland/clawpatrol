import { SectionLabel } from "../components/SectionLabel";

const PROBLEMS = [
  {
    title: "Your agent shouldn't see secrets",
    body:
      "Every API key in the agent's env is one you've handed " +
      "over. If the process is compromised (and prompts can " +
      "compromise it), the keys leak with it. Rotation is hard, " +
      "and you can't easily revoke a single action's worth of " +
      "access.",
  },
  {
    title: "Granting access doesn't gate actions",
    body:
      "OAuth scopes grant the agent broad permission inside a " +
      "service: any action the scope allows. A prompt-injected " +
      "agent will use that permission against you. You need to " +
      "check what each request does, not just whether the agent " +
      "is allowed to send something.",
  },
  {
    title: "You can't see what your agents do",
    body:
      "A fleet of agents making thousands of requests across " +
      "dozens of services leaves no shared trace. Debugging " +
      "\"what did my agent just do?\" means per-service log " +
      "spelunking, and by the time you notice the bad request, " +
      "it's already gone through.",
  },
];

export function ProblemSection() {
  return (
    <section class="max-w-5xl mx-auto px-6 sm:px-8 pt-20 pb-16 sm:pt-32 sm:pb-28 border-t border-navy-200/50">
      <SectionLabel>The problem</SectionLabel>
      <div class="max-w-2xl mx-auto space-y-12 sm:space-y-20">
        {PROBLEMS.map(({ title, body }, i) => (
          <div key={title} class="grid grid-cols-[auto_1fr] gap-3 sm:gap-6">
            <div class="flex items-center justify-center min-w-10 sm:min-w-16">
              <span class="text-5xl sm:text-7xl font-bold font-display select-none text-rust">
                {i + 1}
              </span>
            </div>
            <div class="py-1">
              <h3 class="text-2xl sm:text-3xl font-display font-bold text-console-dark mb-3">
                {title}
              </h3>
              <p class="text-base text-text-muted">{body}</p>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
