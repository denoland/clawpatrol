import { SectionLabel } from "../components/SectionLabel";

function SecretInjectionDiagram() {
  return (
    <svg
      viewBox="0 0 320 100"
      class="w-full h-auto mb-6"
      role="img"
      aria-label="Agent request with SECRET placeholder flowing through Unclaw and emerging with a real credential"
    >
      <defs>
        <marker
          id="si-arrow"
          viewBox="0 0 10 10"
          refX="8"
          refY="5"
          markerWidth="5"
          markerHeight="5"
          orient="auto-start-reverse"
        >
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#5d8a72" />
        </marker>
      </defs>

      {/* Left: agent request with placeholder */}
      <rect
        x="1"
        y="10"
        width="108"
        height="80"
        rx="4"
        fill="#f0ebe3"
        stroke="#c2d4cc"
        stroke-width="1.5"
      />
      <rect x="1" y="10" width="108" height="14" rx="4" fill="#c2d4cc" />
      <rect x="1" y="20" width="108" height="4" fill="#c2d4cc" />
      <circle cx="9" cy="17" r="1.5" fill="#5d8a72" />
      <circle cx="15" cy="17" r="1.5" fill="#5d8a72" />
      <circle cx="21" cy="17" r="1.5" fill="#5d8a72" />
      <text
        x="8"
        y="38"
        font-family="'JetBrains Mono', monospace"
        font-size="7"
        fill="#2a342f"
      >
        POST /v1/chat
      </text>
      <text
        x="8"
        y="52"
        font-family="'JetBrains Mono', monospace"
        font-size="7"
        fill="#6b7770"
      >
        Authorization:
      </text>
      <rect
        x="8"
        y="57"
        width="72"
        height="12"
        rx="2"
        fill="var(--color-accent)"
        opacity="0.35"
      />
      <text
        x="12"
        y="66"
        font-family="'JetBrains Mono', monospace"
        font-size="7"
        fill="#2a342f"
      >
        {"{{SECRET}}"}
      </text>
      <rect x="8" y="76" width="60" height="3" rx="1" fill="#c2d4cc" />
      <rect x="8" y="82" width="48" height="3" rx="1" fill="#c2d4cc" />

      {/* Arrow left → proxy */}
      <path
        d="M 112 50 L 129 50"
        stroke="#5d8a72"
        stroke-width="1.5"
        fill="none"
        marker-end="url(#si-arrow)"
      />

      {/* Middle proxy — official Unclaw logo */}
      <image
        href="/unclaw-logo.svg"
        x="132"
        y="40"
        width="56"
        height="20.4"
        preserveAspectRatio="xMidYMid meet"
      />

      {/* Arrow proxy → right */}
      <path
        d="M 191 50 L 208 50"
        stroke="#5d8a72"
        stroke-width="1.5"
        fill="none"
        marker-end="url(#si-arrow)"
      />

      {/* Right: upstream request with real secret */}
      <rect
        x="211"
        y="10"
        width="108"
        height="80"
        rx="4"
        fill="#f0ebe3"
        stroke="#c2d4cc"
        stroke-width="1.5"
      />
      <rect x="211" y="10" width="108" height="14" rx="4" fill="#c2d4cc" />
      <rect x="211" y="20" width="108" height="4" fill="#c2d4cc" />
      <circle cx="219" cy="17" r="1.5" fill="#5d8a72" />
      <circle cx="225" cy="17" r="1.5" fill="#5d8a72" />
      <circle cx="231" cy="17" r="1.5" fill="#5d8a72" />
      <text
        x="218"
        y="38"
        font-family="'JetBrains Mono', monospace"
        font-size="7"
        fill="#2a342f"
      >
        POST /v1/chat
      </text>
      <text
        x="218"
        y="52"
        font-family="'JetBrains Mono', monospace"
        font-size="7"
        fill="#6b7770"
      >
        Authorization:
      </text>
      <rect
        x="218"
        y="57"
        width="88"
        height="12"
        rx="2"
        fill="#5d8a72"
        opacity="0.25"
      />
      <text
        x="222"
        y="66"
        font-family="'JetBrains Mono', monospace"
        font-size="7"
        fill="#3b5f4f"
      >
        sk-ant-abc123...
      </text>
      <rect x="218" y="76" width="60" height="3" rx="1" fill="#c2d4cc" />
      <rect x="218" y="82" width="48" height="3" rx="1" fill="#c2d4cc" />
    </svg>
  );
}

function AnalyticsDiagram() {
  return (
    <svg
      viewBox="0 0 320 100"
      class="w-full h-auto mb-6"
      role="img"
      aria-label="Area chart of outbound requests over time with metric labels"
    >
      {/* Header labels */}
      <text
        x="0"
        y="10"
        font-family="'Overpass', sans-serif"
        font-size="7"
        font-weight="600"
        fill="#2a342f"
        letter-spacing="1"
      >
        REQUESTS / SEC
      </text>
      <text
        x="320"
        y="10"
        text-anchor="end"
        font-family="'JetBrains Mono', monospace"
        font-size="7"
        fill="#3b5f4f"
      >
        +12.4%
      </text>

      {/* Dashed grid lines */}
      <g opacity="0.4">
        <line
          x1="0"
          y1="30"
          x2="320"
          y2="30"
          stroke="#c2d4cc"
          stroke-width="1"
          stroke-dasharray="2 4"
        />
        <line
          x1="0"
          y1="55"
          x2="320"
          y2="55"
          stroke="#c2d4cc"
          stroke-width="1"
          stroke-dasharray="2 4"
        />
        <line
          x1="0"
          y1="80"
          x2="320"
          y2="80"
          stroke="#c2d4cc"
          stroke-width="1"
          stroke-dasharray="2 4"
        />
      </g>

      {/* Area fill */}
      <path
        d="M 0 72 L 26 62 L 52 68 L 78 50 L 104 58 L 130 42 L 156 48 L 182 30 L 208 38 L 234 22 L 260 28 L 286 18 L 320 24 L 320 90 L 0 90 Z"
        fill="var(--color-accent)"
        fill-opacity="0.22"
      />
      {/* Line */}
      <path
        d="M 0 72 L 26 62 L 52 68 L 78 50 L 104 58 L 130 42 L 156 48 L 182 30 L 208 38 L 234 22 L 260 28 L 286 18 L 320 24"
        stroke="var(--color-accent)"
        stroke-width="1.5"
        fill="none"
        stroke-linecap="round"
        stroke-linejoin="round"
      />
      {/* Markers */}
      <circle cx="78" cy="50" r="2" fill="var(--color-accent)" />
      <circle cx="182" cy="30" r="2" fill="var(--color-accent)" />
      <circle cx="286" cy="18" r="2" fill="var(--color-accent)" />
      <circle cx="286" cy="18" r="4" fill="var(--color-accent)" fill-opacity="0.25" />
    </svg>
  );
}

export function HowItWorksSection() {
  return (
    <section class="py-24 sm:py-32 bg-green-light">
      <div class="max-w-5xl mx-auto px-8">
        <SectionLabel>How it works</SectionLabel>

        <div class="grid md:grid-cols-2 gap-6">
          <div class="p-8 rounded-sm bg-cream-dark border border-green-light">
            <h3 class="text-sm uppercase tracking-[0.2em] mb-4 text-console-dark font-display font-semibold">
              Secret injection
            </h3>
            <SecretInjectionDiagram />
            <ul class="text-[15px] leading-relaxed text-text-muted font-sans list-disc pl-5 space-y-2 marker:text-green-med">
              <li>Placeholders swapped for real credentials at the proxy</li>
              <li>Inject into headers, body, or mTLS</li>
              <li>Secrets never reach agent memory</li>
              <li>Anti-exfiltration blocks reflection attacks</li>
              <li>Shared secrets with per-agent access control</li>
            </ul>
          </div>
          <div class="p-8 rounded-sm bg-cream-dark border border-green-light">
            <h3 class="text-sm uppercase tracking-[0.2em] mb-4 text-console-dark font-display font-semibold">
              Analytics
            </h3>
            <AnalyticsDiagram />
            <ul class="text-[15px] leading-relaxed text-text-muted font-sans list-disc pl-5 space-y-2 marker:text-green-med">
              <li>Every outbound request logged in real time</li>
              <li>
                LLM costs, tokens, cache hits, and latency across all services
              </li>
              <li>Drill into full headers, body, and formatted prompts</li>
            </ul>
          </div>
        </div>
        <div class="text-center mt-24 sm:mt-32">
          <span
            class="inline-block text-[11px]
              font-semibold uppercase tracking-[0.2em]
              px-4 py-1.5 font-display bg-accent text-console-dark"
          >
            Coming soon
          </span>
          <p class="text-sm mt-4 font-sans text-text-muted">
            JavaScript policy engine, AI proctoring, and human-in-the-loop
            approval.
          </p>
        </div>
      </div>
    </section>
  );
}
