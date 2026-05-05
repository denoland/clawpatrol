-- Add per-credential profile metadata so the dashboard can render the
-- real user identity (avatar + login) for each connected OAuth owner,
-- not the generic provider icon.
--
-- Populated after a successful OAuth exchange by fetching the
-- provider's userinfo endpoint (e.g. github.com/user → login +
-- avatar_url). Both columns are optional — absent for providers
-- without an OAuthProfileEnricher and for legacy credentials saved
-- before this migration.

ALTER TABLE credentials ADD COLUMN display_name TEXT;
ALTER TABLE credentials ADD COLUMN avatar_url   TEXT;
