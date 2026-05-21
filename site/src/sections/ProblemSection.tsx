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
  // Candidate cards we considered and dropped. Kept here so the next
  // edit pass starts from drafted copy instead of a blank line.
  //
  // {
  //   title: "The agent is someone else’s code",
  //   body: "Claude Code, Codex, Cursor — the agents your team " +
  //     "actually uses are third-party binaries. Any enforcement " +
  //     "that lives inside the agent depends on a vendor you don’t " +
  //     "control. The gate has to sit outside.",
  // },
  // {
  //   title: "Production isn’t on the public internet",
  //   body: "Your Postgres lives in a VPC. Your Kubernetes API is " +
  //     "private. The agent’s laptop or sandbox can’t reach either " +
  //     "without somebody routing the traffic on its behalf.",
  // },
  // {
  //   title: "HTTP isn’t the only protocol",
  //   body: "Agents shell out to psql, kubectl, ssh, and friends. " +
  //     "Allow / deny decisions need to understand SQL verbs, k8s " +
  //     "verbs, and SSH channels — not just URLs and methods.",
  // },
];

export function ProblemSection() {
  return (
    <section class="max-w-5xl mx-auto px-6 sm:px-8 pt-20 pb-16 sm:pt-32 sm:pb-28">
      <SectionLabel>The problem</SectionLabel>
      <div class="max-w-2xl mx-auto space-y-12 sm:space-y-20">
        {PROBLEMS.map(({ title, body }, i) => (
          <div key={title} class="grid grid-cols-[auto_1fr] gap-3 sm:gap-6">
            <div class="flex items-center justify-center min-w-10 sm:min-w-16">
              <span class="text-5xl sm:text-7xl font-display select-none text-rust">
                {i + 1}
              </span>
            </div>
            <div class="py-1">
              <h3 class="text-2xl sm:text-3xl font-display text-console-dark mb-3">
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
