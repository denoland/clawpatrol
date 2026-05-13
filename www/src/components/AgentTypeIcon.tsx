// Agent type icon — same source as slop.dev (iconify CDN simple-icons
// for Claude/OpenAI; inline shell glyph).

export function AgentTypeIcon({ type, className = "" }: { type?: string; className?: string }) {
  const t = type || "other";
  if (t === "claude")
    return (
      <img
        src="https://api.iconify.design/simple-icons:claude.svg?color=%23d97706"
        className={className}
        alt="Claude"
        draggable={false}
      />
    );
  if (t === "codex")
    return (
      <img
        src="https://api.iconify.design/simple-icons:openai.svg"
        className={className}
        alt="Codex"
        draggable={false}
      />
    );
  if (t === "shell")
    return (
      <svg
        className={className + " text-rust-700"}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M4 17l6-6-6-6" />
        <path d="M12 19h8" />
      </svg>
    );
  return (
    <svg className={className + " text-text-muted"} viewBox="0 0 24 24" fill="currentColor">
      <circle cx="12" cy="12" r="4" />
    </svg>
  );
}
