import { SectionLabel } from "../components/SectionLabel";

/* ──────────────────────────────────────────────────────────────────────
   The "rules" pillar — the centerpiece of the new landing page.
   Frames the policy engine + dual-approver model (LLM judge + human review)
   with a real HCL snippet and a 4-up decision matrix.
   ──────────────────────────────────────────────────────────────────── */

const DECISIONS: { label: string; verdict: string; body: string }[] = [
  {
    label: "Allow",
    verdict: "allow",
    body:
      "Boring requests pass through with no overhead. " +
      "Read-only GETs, internal hosts, anything you've green-lit.",
  },
  {
    label: "Deny",
    verdict: "deny",
    body:
      "Hard stop. Returns a reason to the agent so it knows why. " +
      "DROP TABLE on prod. Writes to repos you didn't authorize.",
  },
  {
    label: "LLM judge",
    verdict: "require_llm",
    body:
      "Cheap, automated review. Hand the request to an LLM " +
      "with your custom prompt — it reads the payload and votes.",
  },
  {
    label: "Human In The Loop",
    verdict: "require_human",
    body:
      "Park the request. Ping Slack, the dashboard, or your own " +
      "webhook. Resume on approval. Time out closed if no one's home.",
  },
];

function RuleCodeBlock() {
  /* Hand-tinted pseudo-syntax-highlighted HCL. Avoids pulling in a
     full highlighter for one snippet. */
  return (
    <pre
      class="text-[13px] sm:text-sm  font-mono
        bg-console-dark text-canvas/85 squircle-md p-6 overflow-x-auto
        border border-navy-700"
    >
      <code>
        <span class="text-text-subtle">
          # Block destructive SQL on prod{"\n"}
        </span>
        <span class="text-rust-300">rule</span>{" "}
        <span class="text-butter-300">"sql_rule"</span>{" "}
        <span class="text-butter-300">"no-prod-drops"</span>
        {" {\n"}
        {"  "}
        <span class="text-rust-300">match</span>
        {"   = { "}
        <span class="text-canvas/70">verb</span>
        {" = ["}
        <span class="text-butter-300">"DROP"</span>
        {", "}
        <span class="text-butter-300">"TRUNCATE"</span>
        {"] }\n"}
        {"  "}
        <span class="text-rust-300">verdict</span>
        {" = "}
        <span class="text-butter-300">"deny"</span>
        {"\n}\n\n"}
        <span class="text-text-subtle">
          # Slack-approve any GitHub write{"\n"}
        </span>
        <span class="text-rust-300">rule</span>{" "}
        <span class="text-butter-300">"http_rule"</span>{" "}
        <span class="text-butter-300">"github-writes"</span>
        {" {\n"}
        {"  "}
        <span class="text-rust-300">endpoint</span>
        {" = github-api\n"}
        {"  "}
        <span class="text-rust-300">match</span>
        {"    = { "}
        <span class="text-canvas/70">method</span>
        {" = ["}
        <span class="text-butter-300">"POST"</span>
        {", "}
        <span class="text-butter-300">"PUT"</span>
        {", "}
        <span class="text-butter-300">"DELETE"</span>
        {"] }\n"}
        {"  "}
        <span class="text-rust-300">approve</span>
        {"  = [ops]\n"}
        {"}\n\n"}
        <span class="text-text-subtle">
          # Hand sensitive reads to an LLM judge{"\n"}
        </span>
        <span class="text-rust-300">approver</span>{" "}
        <span class="text-butter-300">"llm_approver"</span>{" "}
        <span class="text-butter-300">"secret-judge"</span>
        {" {\n"}
        {"  "}
        <span class="text-rust-300">model</span>
        {"  = "}
        <span class="text-butter-300">"claude-haiku-4-5"</span>
        {"\n  "}
        <span class="text-rust-300">policy</span>
        {" = "}
        <span class="text-butter-300">
          "reject changes with bad words"
        </span>
        {"\n}"}
      </code>
    </pre>
  );
}

const colorClasses = [
  "bg-rust-100",
  "bg-navy-100",
  "bg-butter-100",
  "bg-canvas",
];

export function RulesSection() {
  return (
    <section class="bg-canvas-muted py-24 sm:py-32">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <SectionLabel>Approval rules</SectionLabel>

        <div class="grid lg:grid-cols-[2fr_3fr] gap-8 lg:gap-16 xl:gap-32 items-start mb-20">
          <div>
            <h3 class="text-3xl sm:text-4xl md:text-5xl lg:text-[2.75rem] font-display font-bold  mb-6 text-text">
              You write the rules.{" "}
              <span class="text-rust">Claw Patrol enforces them.</span>
            </h3>
            <p class="text-base  text-text-muted mb-5 max-w-xl">
              Every outbound request — HTTP, SQL, SSH, Kubernetes — runs through
              a rule engine before it leaves your machine. Match on method,
              host, SQL verbs and tables, k8s namespaces, plugin- defined
              facets. Decide what happens next.
            </p>
            <p class="text-base  text-text-muted max-w-xl">
              Edits are hot. Save a rule in the dashboard, the next request sees
              it. No restarts, no redeploys, no waiting.
            </p>
          </div>
          <RuleCodeBlock />
        </div>

        <div>
          <p class="text-xs uppercase tracking-[0.25em]  font-bold text-text-muted mb-5">
            Four verdicts. Mix freely.
          </p>
          <div class="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {DECISIONS.map((d, i) => (
              <div
                key={d.verdict}
                class="bg-transparent relative squircle-md p-6"
              >
                <div className=" absolute w-full h-full border-navy border-2 squircle-md inset-0 z-10"></div>
                <div class="flex items-baseline justify-between mb-3 relative z-10">
                  <h4 class="text-lg font-display font-bold text-text">
                    {d.label}
                  </h4>
                  <code class="text-[10px] font-mono text-text-subtle">
                    {d.verdict}
                  </code>
                </div>
                <p class="text-sm relative z-10 text-text-muted">{d.body}</p>
                <div
                  className={
                    `isolate absolute w-full h-full squircle-md top-1.5 left-2 z-0 ` +
                    colorClasses[i]
                  }
                ></div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
