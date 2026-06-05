// Vertical flow: agents on top, the Claw Patrol proxy in the middle,
// destinations on the bottom. Requests flow downward through the
// stack of policy switches inside the proxy.
export function FlowDiagram() {
  return (
    <div
      class="flex flex-col items-stretch w-full md:max-w-[24rem] select-none"
      role="img"
      aria-label="Your agents send requests through Claw Patrol down to the tools and systems they act on"
    >
      <AgentsNode />

      <Riser />

      <CenterNode label="Claw Patrol" />

      <Riser />

      <ProductionNode />
    </div>
  );
}

function AgentsNode() {
  return (
    <div
      class=" w-full border border-navy-200
        text-text px-5 py-5 text-center"
    >
      <div class="font-display font-bold text-xl leading-none">
        Your agent(s)
      </div>
      <div class="flex justify-center items-end gap-6 mt-4">
        <AgentItem name="Claude" icon="/icons/claude.svg" />
        <AgentItem name="Codex" icon="/icons/openai.svg" />
        <AgentItem name="OpenClaw" icon="/icons/openclaw.svg" />
        <AgentItem name="Others" />
      </div>
    </div>
  );
}

function AgentItem({ name, icon }: { name: string; icon?: string }) {
  return (
    <div class="flex flex-col items-center gap-2 min-w-0">
      {icon ? (
        <img src={icon} alt="" class="w-6 h-6" aria-hidden="true" />
      ) : (
        <RobotGlyph />
      )}
      <div
        class="font-display font-semibold text-[11.5px] text-text-muted
          leading-tight text-center text-balance"
      >
        {name}
      </div>
    </div>
  );
}

function ProductionNode() {
  return (
    <div
      class=" w-full border border-navy-200
        text-text px-5 py-5 text-center"
    >
      <div class="font-display font-bold text-xl leading-none">
        Tools &amp; systems
      </div>
      <div class="grid grid-cols-4 gap-4 mt-4 place-items-center">
        <ToolIcon src="/icons/postgres-mono.svg" />
        <ToolIcon src="/icons/clickhouse.svg" />
        <ToolIcon src="/icons/kubernetes.svg" />
        <ToolIcon src="/icons/aws.svg" />
        <ToolIcon src="/icons/gcp.svg" />
        <ToolIcon src="/icons/github-mono.svg" />
        <ToolIcon src="/icons/slack.svg" />
        <ToolIcon src="/icons/vultr.svg" />
      </div>
    </div>
  );
}

function ToolIcon({ src }: { src: string }) {
  return (
    <img
      src={src}
      alt=""
      class="w-6 h-6 brightness-0 opacity-70"
      aria-hidden="true"
    />
  );
}

function Riser() {
  return (
    <div class="w-full flex justify-center my-2">
      <svg
        width="16"
        height="28"
        viewBox="0 0 16 28"
        class="text-navy-300"
        aria-hidden="true"
      >
        <path
          d="M 8 0 V 23"
          stroke="currentColor"
          stroke-width="1.5"
          stroke-linecap="round"
          fill="none"
        />
        <path
          d="M 2 18 L 8 24 L 14 18"
          stroke="currentColor"
          stroke-width="1.5"
          stroke-linecap="round"
          stroke-linejoin="round"
          fill="none"
        />
      </svg>
    </div>
  );
}

function SwitchTag({ label }: { label: string }) {
  return (
    <div className="bg-navy text-xs font-mono uppercase text-canvas w-max max-w-full mx-auto py-0.5 px-2">
      {label}
    </div>
  );
}

function CenterNode({ label }: { label: string }) {
  // Light surface keyed to the header’s bg-navy-100 so the proxy node
  // reads as the same brand surface; full Claw Patrol logo (icon +
  // wordmark) is the same public asset the header uses.
  return (
    <div
      class=" w-full border border-navy text-text
      px-5 py-5 pt-14 relative text-center mt-6 bg-linear-to-b from-canvas to-navy-50 "
    >
      <img
        src="/claw-patrol-logo.svg"
        alt={label}
        class="h-auto w-64 mx-auto px-4 absolute -top-6.5 left-[calc(50%-8.5rem)] bg-canvas"
      />
      <SwitchTag label="Rules - action allowed?" />
      <Riser />
      <SwitchTag label="Approvers - action requires approval?" />
      <Riser />
      <SwitchTag label="Inject credentials" />
      <Riser />
      <SwitchTag label="Log every action" />
    </div>
  );
}

function RobotGlyph() {
  return (
    <svg
      viewBox="0 0 24 24"
      class="w-6 h-6 text-navy-500"
      fill="none"
      stroke="currentColor"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path d="M 12 3 V 6" />
      <circle cx="12" cy="2" r="0.8" fill="currentColor" stroke="none" />
      <rect x="4" y="7" width="16" height="13" rx="2" />
      <circle cx="9" cy="13" r="1.2" fill="currentColor" stroke="none" />
      <circle cx="15" cy="13" r="1.2" fill="currentColor" stroke="none" />
      <path d="M 10 17 H 14" />
    </svg>
  );
}
