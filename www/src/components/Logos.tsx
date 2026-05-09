// Brand logos from iconify CDN (same source as slop.dev). Inline OS
// icons stay local.

const ICON_BASE = "https://api.iconify.design/simple-icons:";

export function ClaudeLogo({ className = "" }: { className?: string }) {
  return (
    <img
      src={ICON_BASE + "claude.svg?color=%23d97706"}
      className={className}
      alt="Claude"
      draggable={false}
    />
  );
}

export function OpenAILogo({ className = "" }: { className?: string }) {
  return (
    <img src={ICON_BASE + "openai.svg"} className={className} alt="OpenAI" draggable={false} />
  );
}

export function GithubLogo({ className = "" }: { className?: string }) {
  return (
    <img src={ICON_BASE + "github.svg"} className={className} alt="GitHub" draggable={false} />
  );
}

export function ShellGlyph({ className = "" }: { className?: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="#7c3aed" className={className}>
      <path
        d="M4 17l6-6-6-6m8 14h8"
        stroke="#7c3aed"
        strokeWidth="2"
        fill="none"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// IntegrationIcon picks an icon from the credential's plugin type
// first (e.g. "postgres_credential" → Postgres logo), falling back to
// the credential's bare name for the legacy claude/codex/github built-
// ins where the bare name happens to match the brand. Unknown types
// get a neutral key glyph rather than empty space, so dashboard rows
// stay visually anchored.
export function IntegrationIcon({
  id,
  type,
  className = "",
}: {
  id: string;
  type?: string;
  className?: string;
}) {
  const t = type ?? "";
  if (t === "anthropic_oauth_subscription" || t === "anthropic_manual_key" || id === "claude")
    return <ClaudeLogo className={className} />;
  if (t === "openai_codex_oauth" || id === "codex") return <OpenAILogo className={className} />;
  if (t === "github_oauth" || id === "github") return <GithubLogo className={className} />;
  if (t === "postgres_credential")
    return <BrandIcon name="postgresql" color="%23336791" className={className} />;
  if (t === "clickhouse_credential")
    return <BrandIcon name="clickhouse" color="%23faff69" className={className} />;
  if (t === "slack_tokens") return <SlackGlyph className={className} />;
  if (t === "telegram_bot_token")
    return <BrandIcon name="telegram" color="%2326a5e4" className={className} />;
  if (t === "gemini_api_key")
    return <BrandIcon name="googlegemini" color="%238e75b2" className={className} />;
  if (t === "notion_oauth") return <BrandIcon name="notion" className={className} />;
  if (t === "aws_eks_credential")
    return <BrandIcon name="amazoneks" color="%23ff9900" className={className} />;
  if (t === "mtls_credential") return <KeyGlyph className={className} />;
  return <KeyGlyph className={className} />;
}

// SlackGlyph is the official 4-color Slack logo, embedded inline so
// it doesn't depend on simpleicons' Slack entry (Salesforce pulled
// Slack from simpleicons over a trademark dispute and replaced it
// with the Salesforce swirl).
function SlackGlyph({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="70 70 130 130" xmlns="http://www.w3.org/2000/svg" className={className}>
      <path
        fill="#E01E5A"
        d="M99.4 151.2c0 7.1-5.8 12.9-12.9 12.9-7.1 0-12.9-5.8-12.9-12.9 0-7.1 5.8-12.9 12.9-12.9h12.9v12.9zm6.5 0c0-7.1 5.8-12.9 12.9-12.9 7.1 0 12.9 5.8 12.9 12.9v32.3c0 7.1-5.8 12.9-12.9 12.9-7.1 0-12.9-5.8-12.9-12.9v-32.3z"
      />
      <path
        fill="#36C5F0"
        d="M118.8 99.4c-7.1 0-12.9-5.8-12.9-12.9 0-7.1 5.8-12.9 12.9-12.9 7.1 0 12.9 5.8 12.9 12.9v12.9h-12.9zm0 6.5c7.1 0 12.9 5.8 12.9 12.9 0 7.1-5.8 12.9-12.9 12.9H86.5c-7.1 0-12.9-5.8-12.9-12.9 0-7.1 5.8-12.9 12.9-12.9h32.3z"
      />
      <path
        fill="#2EB67D"
        d="M170.6 118.8c0-7.1 5.8-12.9 12.9-12.9 7.1 0 12.9 5.8 12.9 12.9 0 7.1-5.8 12.9-12.9 12.9h-12.9v-12.9zm-6.5 0c0 7.1-5.8 12.9-12.9 12.9-7.1 0-12.9-5.8-12.9-12.9V86.5c0-7.1 5.8-12.9 12.9-12.9 7.1 0 12.9 5.8 12.9 12.9v32.3z"
      />
      <path
        fill="#ECB22E"
        d="M151.2 170.6c7.1 0 12.9 5.8 12.9 12.9 0 7.1-5.8 12.9-12.9 12.9-7.1 0-12.9-5.8-12.9-12.9v-12.9h12.9zm0-6.5c-7.1 0-12.9-5.8-12.9-12.9 0-7.1 5.8-12.9 12.9-12.9h32.3c7.1 0 12.9 5.8 12.9 12.9 0 7.1-5.8 12.9-12.9 12.9h-32.3z"
      />
    </svg>
  );
}

function BrandIcon({
  name,
  color = "",
  className = "",
}: {
  name: string;
  color?: string;
  className?: string;
}) {
  const url = ICON_BASE + name + ".svg" + (color ? "?color=" + color : "");
  return <img src={url} className={className} alt={name} draggable={false} />;
}

function KeyGlyph({ className = "" }: { className?: string }) {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="#737373"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
    </svg>
  );
}

// EditGlyph: small pencil for inline action buttons. Matches the stroke
// weight + neutral color of KeyGlyph so the action affordances look
// like a set, not a mismatched grab-bag.
export function EditGlyph({ className = "" }: { className?: string }) {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <path d="M12 20h9" />
      <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z" />
    </svg>
  );
}

// ── device / OS icons (kept local) ─────────────────────────────────

type IconProps = { className?: string };
const baseProps = {
  viewBox: "0 0 24 24",
  fill: "currentColor",
  xmlns: "http://www.w3.org/2000/svg",
};

function MacIcon({ className = "" }: IconProps) {
  return (
    <svg className={className} {...baseProps} aria-label="macOS">
      <path d="M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09zM12 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z" />
    </svg>
  );
}

function LinuxIcon({ className = "" }: IconProps) {
  // Generic terminal/server glyph. Tux looks weird at small sizes;
  // we don't have distro info to show Ubuntu/Debian/Arch logos
  // (would need /etc/os-release reported from the client).
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-label="Linux"
    >
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M7 9l3 3-3 3M13 15h4" />
    </svg>
  );
}

function WindowsIcon({ className = "" }: IconProps) {
  return (
    <svg className={className} {...baseProps} aria-label="Windows">
      <path d="M0 3.449L9.75 2.1V11.551H0M10.95 1.949L24 0V11.4H10.95M0 12.6H9.75V22.051L0 20.701M10.95 12.752H24V24L10.95 22.051" />
    </svg>
  );
}

function DesktopIcon({ className = "" }: IconProps) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      xmlns="http://www.w3.org/2000/svg"
    >
      <rect width="20" height="14" x="2" y="3" rx="2" />
      <line x1="8" x2="16" y1="21" y2="21" />
      <line x1="12" x2="12" y1="17" y2="21" />
    </svg>
  );
}

export function DeviceIcon({
  os,
  hostname,
  ua,
  className = "",
}: {
  os?: string;
  hostname?: string;
  ua?: string;
  className?: string;
}) {
  const s = ((os || "") + " " + (hostname || "") + " " + (ua || "")).toLowerCase();
  if (/mac|darwin|os x|macbook|imac/.test(s)) return <MacIcon className={className} />;
  if (/linux|ubuntu|debian|fedora|arch|rocky|alpine|nixos/.test(s))
    return <LinuxIcon className={className} />;
  if (/windows|win\b|win32/.test(s)) return <WindowsIcon className={className} />;
  return <DesktopIcon className={className} />;
}
