import { SectionLabel } from "../components/SectionLabel";

const PROBLEMS = [
  {
    title: "Access isn’t action control",
    body: "OAuth scopes, IAM roles, and Kubernetes RBAC decide which " +
      "services an agent can reach. They don’t decide what it can do " +
      "once connected. The agent that can talk to Postgres can DROP " +
      "TABLE as easily as SELECT.",
  },
  {
    title: "Your agent shouldn’t see secrets",
    body: "If the agent is compromised by prompt injection, the credentials " +
      "it holds leak with it. Keys should live somewhere the agent can " +
      "never see.",
  },
  {
    title: "You can’t see what the agent did",
    body: "An agent’s work fans out across Postgres, Kubernetes, GitHub, " +
      "and Slack. Reconstructing what it actually did means stitching " +
      "together logs from each service. With a fleet, the question " +
      "‘what just happened?’ has no straight answer.",
  },
];

export function ProblemSection() {
  return (
    <section class="max-w-6xl mx-auto px-6 sm:px-8 pt-20 pb-16 sm:pt-32 sm:pb-28">
      <div class="max-w-2xl mx-auto space-y-12 text-center">
        <SectionLabel>The problem</SectionLabel>
        {PROBLEMS.map(({ title, body }) => (
          <div key={title} class="py-1">
            <h3 class="text-2xl sm:text-3xl font-display text-console-dark mb-3 text-balance">
              {title}
            </h3>
            <p class="text-base text-text-muted text-pretty">{body}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
