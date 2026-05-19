-- 0013_credential_client_id — carry the dynamically registered OAuth
-- client_id on each credential row. RFC 7591 dynamic client registration
-- (used by mcp.notion.com / Notion MCP) produces a unique client_id at
-- connect time; without it, refresh would have to fall back to the
-- integration's static ClientID, which dynamic-registration flows do not
-- ship. Static-ClientID flows (github, anthropic, codex) leave this NULL
-- and continue to refresh against their plugin-declared client_id.

ALTER TABLE credentials ADD COLUMN client_id TEXT;

INSERT INTO _schema (version) VALUES (13);
