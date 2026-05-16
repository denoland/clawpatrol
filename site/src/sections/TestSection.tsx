import { SectionLabel } from "../components/SectionLabel";

/* ──────────────────────────────────────────────────────────────────────
   `clawpatrol test` — regression-test CLI for policy changes. Replays
   recorded actions against a candidate config and asserts the verdicts
   still match. Drops into CI as a single binary; no gateway, no auth.
   The terminal output below is real: run against deno.hcl with one
   verdict flipped on the k8s-no-secrets rule.
   ──────────────────────────────────────────────────────────────────── */

function TestOutput() {
  const ok = (path: string) => (
    <>
      ok   {path}
      {"\n"}
    </>
  );
  return (
    <pre
      class="min-w-0 text-[12.5px] sm:text-[13px] font-mono leading-relaxed
        bg-navy text-canvas/85 squircle-md p-6 overflow-x-auto
        border border-navy-700"
    >
      <code>
        <span class="text-canvas/40">$ </span>
        clawpatrol test deno.hcl tests/
        {"\n"}
        {ok("tests/anthropic-implicit-allow.json")}
        {ok("tests/clickhouse-default-deny.json")}
        {ok("tests/clickhouse-read.json")}
        {ok("tests/deno-com-require-approval.json")}
        {ok("tests/deno-deploy-read.json")}
        {ok("tests/github-api-implicit-allow.json")}
        {ok("tests/k8s-allow-meta.json")}
        {ok("tests/k8s-debug-pods.json")}
        {ok("tests/k8s-default-deny.json")}
        <span class="text-rust-300 font-bold">FAIL</span>
        {" tests/k8s-no-secrets.json\n"}
        {"  "}
        <span class="text-canvas/55">want</span>
        {" verdict="}
        <span class="text-butter-300">"deny"</span>
        {"       rule="}
        <span class="text-butter-300">"k8s-no-secrets"</span>
        {"\n  "}
        <span class="text-canvas/55">got </span>
        {" verdict="}
        <span class="text-butter-300">"allow"</span>
        {"      rule="}
        <span class="text-butter-300">"k8s-no-secrets"</span>
        {"\n"}
        {ok("tests/k8s-reads.json")}
        {ok("tests/orb-avocet2-immutable-operations-allow.json")}
        {ok("tests/pg-staging-banned-functions.json")}
        {ok("tests/pg-staging-default-deny.json")}
        {ok("tests/pg-staging-reads.json")}
        36 action(s) checked,{" "}
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
