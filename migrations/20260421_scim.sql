-- SCIM 2.0 support: deactivation, external IdP id, and resource timestamps on users.
-- SQLite can't ALTER TABLE ADD COLUMN with a non-constant default, so we backfill
-- existing rows with unixepoch() after the fact.
ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN external_id TEXT;
ALTER TABLE users ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;

UPDATE users SET created_at = unixepoch(), updated_at = unixepoch() WHERE created_at = 0;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id
    ON users(external_id) WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_username_lower ON users(lower(username));
CREATE INDEX IF NOT EXISTS idx_users_email_lower ON users(lower(email));
CREATE INDEX IF NOT EXISTS idx_users_active ON users(active);

-- Long-lived bearer tokens for SCIM clients (Okta/Azure/OneLogin). Admin-issued,
-- hashed at rest (SHA-256 of the random token), revocable.
CREATE TABLE IF NOT EXISTS scim_tokens (
    id BLOB PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    created_by BLOB NOT NULL,
    last_used_at INTEGER,
    revoked_at INTEGER,
    FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_scim_tokens_hash ON scim_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_scim_tokens_created_by ON scim_tokens(created_by);
