import { SectionLabel } from "../components/SectionLabel";

const PROBLEMS = [
  {
    title: "Agents are stuck without access",
    body:
      "An agent that can only edit files in a sandbox is a toy. The " +
      "work that matters — running a migration, replying to a " +
      "customer, fixing a deploy — lives behind API calls. But every " +
      "credential you hand the agent is one you've given away.",
  },
  {
    title: "Prompt injection turns every input into instructions",
    body:
      "Tool outputs, RAG hits, MCP responses, file contents the agent " +
      "reads — any of it can hide instructions the model will follow. " +
      "You can't audit the model's intent. The only thing you can " +
      "constrain is what leaves the machine.",
  },
  {
    title: "Today's options are no-access or YOLO",
    body:
      "API keys in env vars, broad OAuth scopes, no checkpoint " +
      "between intent and damage. By the time you notice the agent " +
      "ran DROP TABLE on prod, the table is gone — and you have no " +
      "record of who decided what.",
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
              <span class="text-4xl sm:text-7xl font-extrabold font-display  select-none text-rust">
                {i + 1}
              </span>
            </div>
            <div class="py-1">
              <h3 class="text-2xl font-display font-extrabold text-console-dark mb-3">
                {title}
              </h3>
              <p class="text-base  text-text-muted">{body}</p>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
