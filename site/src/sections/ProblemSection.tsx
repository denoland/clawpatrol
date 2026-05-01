import { SectionLabel } from "../components/SectionLabel";

const PROBLEMS = [
  {
    title: "Secrets in plaintext",
    body:
      "Your OpenClaw gateway token, GitHub PAT, Slack credentials — all " +
      "in plaintext. Skills can access them. One prompt injection and " +
      "they're exfiltrated.",
  },
  {
    title: "Low visibility",
    body:
      "Your agent talks to GitHub, Slack, Anthropic, and 20 other " +
      "services. Hundreds of requests per hour. You can't see what it " +
      "costs or what's failing.",
  },
];

export function ProblemSection() {
  return (
    <section class="max-w-5xl mx-auto px-8 pt-32 pb-28 border-t border-green-light/50">
      <SectionLabel>The problem</SectionLabel>
      <div class="max-w-2xl mx-auto space-y-20">
        {PROBLEMS.map(({ title, body }, i) => (
          <div key={title} class="grid grid-cols-[auto_1fr] gap-6">
            <div class="flex items-center justify-center min-w-16">
              <span class="text-4xl sm:text-6xl font-light font-display leading-none select-none text-accent">
                {i + 1}
              </span>
            </div>
            <div class="py-1">
              <h3 class="text-2xl font-display font-normal text-console-dark mb-3">
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
