export const CREDENTIAL_TYPE_LABEL: Record<string, string> = {
  anthropic_oauth_subscription: "Claude",
  anthropic_manual_key: "Claude (API key)",
  openai_codex_oauth: "Codex",
  github_oauth: "GitHub",
  notion_oauth: "Notion",
  notion_mcp_oauth: "Notion (MCP)",
  postgres_credential: "Postgres",
  clickhouse_credential: "ClickHouse",
  mtls_credential: "mTLS",
  slack_tokens: "Slack",
  telegram_bot_token: "Telegram",
  gemini_api_key: "Gemini",
  aws_credential: "AWS",
  bearer_token: "Bearer token",
  header_token: "Header token",
  cookie_token: "Cookie token",
  tailscale: "Tailscale",
  passthrough: "Passthrough",
};

export function credentialTypeLabel(type: string, fallback: string): string {
  return CREDENTIAL_TYPE_LABEL[type] ?? fallback;
}

// CredentialCategory groups credential types for the settings page
// card grid. Lower rank = surfaced first. The ranks match the order
// LLMs > messaging > databases > 3rd-party > generic-token > other,
// which is the order operators actually wire integrations up in.
export type CredentialCategory =
  | "llm"
  | "messaging"
  | "database"
  | "third_party"
  | "generic"
  | "other";

export const CREDENTIAL_CATEGORY_RANK: Record<CredentialCategory, number> = {
  llm: 0,
  messaging: 1,
  database: 2,
  third_party: 3,
  generic: 4,
  other: 5,
};

const CREDENTIAL_TYPE_CATEGORY: Record<string, CredentialCategory> = {
  anthropic_oauth_subscription: "llm",
  anthropic_manual_key: "llm",
  openai_codex_oauth: "llm",
  gemini_api_key: "llm",
  slack_tokens: "messaging",
  telegram_bot_token: "messaging",
  postgres_credential: "database",
  clickhouse_credential: "database",
  github_oauth: "third_party",
  notion_oauth: "third_party",
  notion_mcp_oauth: "third_party",
  aws_credential: "third_party",
  tailscale: "third_party",
  mtls_credential: "generic",
  bearer_token: "generic",
  header_token: "generic",
  cookie_token: "generic",
  passthrough: "generic",
};

export function credentialCategory(type: string): CredentialCategory {
  return CREDENTIAL_TYPE_CATEGORY[type] ?? "other";
}
