import type { ComponentChildren } from "preact";
import { SectionLabel } from "../components/SectionLabel";

function Problem({
  icon,
  children,
}: {
  icon: ComponentChildren;
  children: ComponentChildren;
}) {
  return (
    <div class="flex flex-col gap-5">
      <div class="size-16 squircle-lg bg-navy text-canvas flex items-center justify-center">
        {icon}
      </div>
      <div>{children}</div>
    </div>
  );
}

// Closed padlock — "access" boundary that lets too much through.
function PadlockIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.75"
      stroke-linecap="round"
      stroke-linejoin="round"
      class="size-8"
      aria-hidden="true"
    >
      <rect x="4" y="11" width="16" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
      <circle cx="12" cy="16" r="1.25" fill="currentColor" stroke="none" />
    </svg>
  );
}

// Key — credentials the agent holds.
function KeyIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.75"
      stroke-linecap="round"
      stroke-linejoin="round"
      class="size-8"
      aria-hidden="true"
    >
      <circle cx="7" cy="17" r="4" />
      <path d="M10 14 20 4" />
      <path d="M16 8l3 3" />
      <path d="M19 5l3 3" />
    </svg>
  );
}

// Eye — visibility / audit of what the agent did.
function EyeIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.75"
      stroke-linecap="round"
      stroke-linejoin="round"
      class="size-8"
      aria-hidden="true"
    >
      <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

function ProblemHeading({ children }: { children: ComponentChildren }) {
  return (
    <h3 class="text-2xl sm:text-3xl font-display text-console-dark mb-3 text-balance">
      {children}
    </h3>
  );
}

function ProblemBody({ children }: { children: ComponentChildren }) {
  return <p class="text-base text-text-muted text-pretty">{children}</p>;
}

export function ProblemSection() {
  return (
    <section class="max-w-6xl mx-auto px-6 sm:px-8 pt-20 pb-16 sm:pt-32 sm:pb-28">
      <div class="space-y-16">
        <SectionLabel class="ml-0">The problem</SectionLabel>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-10 lg:gap-12 items-start">
          <Problem icon={<PadlockIcon />}>
            <ProblemHeading>
              Access shouldn’t be <span class="text-rust">permission</span>
            </ProblemHeading>
            <ProblemBody>
              An agent that can talk to Postgres can DROP TABLE as easily as
              SELECT.
            </ProblemBody>
          </Problem>

          <Problem icon={<KeyIcon />}>
            <ProblemHeading>
              Using keys shouldn’t mean{" "}
              <span class="text-rust">risking them</span>
            </ProblemHeading>
            <ProblemBody>
              If the agent is compromised by prompt injection, the credentials
              it holds leak with it.
            </ProblemBody>
          </Problem>

          <Problem icon={<EyeIcon />}>
            <ProblemHeading>
              You can’t see <span class="text-rust">what happened</span>
            </ProblemHeading>
            <ProblemBody>
              Reconstructing what actually happened means stitching together
              logs from multiple services.
            </ProblemBody>
          </Problem>
        </div>
      </div>
    </section>
  );
}
