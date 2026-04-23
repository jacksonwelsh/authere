-- OIDC provider support: applications table gains a discriminator + OIDC-specific columns,
-- plus a new table for ephemeral authorization codes.

ALTER TABLE applications ADD COLUMN app_type TEXT NOT NULL DEFAULT 'forward_auth';
ALTER TABLE applications ADD COLUMN oidc_client_id TEXT;
ALTER TABLE applications ADD COLUMN oidc_client_secret_hash TEXT;
ALTER TABLE applications ADD COLUMN oidc_redirect_uris TEXT;
ALTER TABLE applications ADD COLUMN oidc_post_logout_redirect_uris TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_applications_oidc_client_id
    ON applications(oidc_client_id) WHERE oidc_client_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS oidc_authorization_codes (
    code_hash TEXT PRIMARY KEY NOT NULL,
    application_id BLOB NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    nonce TEXT,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    auth_time INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_oidc_codes_expires ON oidc_authorization_codes(expires_at);
