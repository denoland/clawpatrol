import { SectionLabel } from "../components/SectionLabel";

/* ──────────────────────────────────────────────────────────────────────
   `clawpatrol test` — regression-test CLI for policy changes. Replays
   recorded actions against a candidate config and asserts the verdicts
   still match. Drops into CI as a single binary; no gateway, no auth.
   ──────────────────────────────────────────────────────────────────── */

function TestOutput() {
  return (
    <pre
      class="min-w-0 text-[13px] sm:text-sm font-mono leading-relaxed
        bg-navy text-canvas/85 squircle-md p-6 overflow-x-auto
        border border-navy-700"
    >
      <code>
        <span class="text-canvas/40">$ </span>
        clawpatrol test github.hcl fixtures/
        {"\n"}
        <span class="text-rust-300 font-bold">FAIL</span>
        {" fixtures/get-user.json\n"}
        {"  "}
        <span class="text-canvas/60">want</span>
        {" verdict="}
        <span class="text-butter-300">"allow"</span>
        {"  rule="}
        <span class="text-butter-300">"github-reads"</span>
        {"\n"}
        {"  "}
        <span class="text-canvas/60">got </span>
        {" verdict="}
        <span class="text-butter-300">"deny"</span>
        {"   rule="}
        <span class="text-butter-300">"github-reads"</span>
        {"\n"}
        1 action(s) checked,{" "}
        <span class="text-rust-300">1 mismatch(es)</span>
      </code>
    </pre>
  );
}

export function TestSection() {
  return (
    <section class="bg-canvas-muted py-24 sm:py-32">
      <div class="max-w-6xl mx-auto px-6 sm:px-8">
        <SectionLabel>Regression tests</SectionLabel>

        <div class="grid grid-cols-1 lg:grid-cols-[2fr_3fr] gap-8 lg:gap-16 xl:gap-32 items-start">
          <div class="min-w-0">
            <h3 class="text-4xl sm:text-5xl md:text-6xl lg:text-[3.25rem] font-display font-bold text-balance mb-6 text-text">
              Test your rules{" "}
              <span class="text-rust">before you ship them.</span>
            </h3>
            <p class="text-base text-text-muted mb-5 max-w-xl">
              Record real actions from the dashboard. Drop the JSON files into
              a fixtures directory. Run <code>clawpatrol test</code> in CI:
              when a policy change flips a verdict, the runner prints the
              diff and fails the build.
            </p>
            <p class="text-base text-text-muted max-w-xl">
              No gateway, no database, no auth. A single binary that loads
              your HCL, replays each fixture against the rule engine, and
              asserts the verdicts still match.
            </p>
          </div>
          <TestOutput />
        </div>
      </div>
    </section>
  );
}
