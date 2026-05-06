import { SectionLabel } from "../components/SectionLabel";

const PROBLEMS = [
  {
    title: "No way to gate writes",
    body:
      "Your agent can DROP TABLE, force-push, send the email, delete the " +
      "repo. By the time you notice, the action's already shipped. " +
      "There's no checkpoint between intent and damage.",
  },
  {
    title: "No audit trail",
    body:
      "When something goes wrong, you can't reconstruct who decided what. " +
      "No record of which model called which API, no record of who — or " +
      "what — approved the destructive action.",
  },
  {
    title: "Secrets in plaintext",
    body:
      "Every API key in the agent's environment is one prompt injection " +
      "away from exfiltration. The agent doesn't need to see your " +
      "credentials to use them — but right now it does.",
  },
];

export function ProblemSection() {
  return (
    <section class="max-w-5xl mx-auto px-8 pt-32 pb-28 border-t border-navy-200/50">
      <SectionLabel>The problem</SectionLabel>
      <div class="max-w-2xl mx-auto space-y-20">
        {PROBLEMS.map(({ title, body }, i) => (
          <div key={title} class="grid grid-cols-[auto_1fr] gap-6">
            <div class="flex items-center justify-center min-w-16">
              <span class="text-4xl sm:text-6xl font-light font-display leading-none select-none text-rust">
                {i + 1}
              </span>
            </div>
            <div class="py-1">
              <h3 class="text-2xl font-display font-black text-console-dark mb-3">
                {title}
              </h3>
              <p class="text-base leading-relaxed text-text-muted">{body}</p>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
