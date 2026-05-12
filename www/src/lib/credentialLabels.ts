export const CREDENTIAL_TYPE_LABEL: Record<string, string> = {
  anthropic_oauth_subscription: "Claude",
  anthropic_manual_key: "Claude (API key)",
  openai_codex_oauth: "Codex",
  github_oauth: "GitHub",
  notion_oauth: "Notion",
  postgres_credential: "Postgres",
  clickhouse_credential: "ClickHouse",
  mtls_credential: "mTLS",
  slack_tokens: "Slack",
  telegram_bot_token: "Telegram",
  gemini_api_key: "Gemini",
  aws_eks_credential: "AWS EKS",
  bearer_token: "Bearer token",
  header_token: "Header token",
  cookie_token: "Cookie token",
  tailscale: "Tailscale",
};

export function credentialTypeLabel(type: string, fallback: string): string {
  return CREDENTIAL_TYPE_LABEL[type] ?? fallback;
}
