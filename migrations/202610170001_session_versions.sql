-- A generation counter invalidates sessions immediately, including tokens issued
-- in the same second as a password change or logout.
ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;

ALTER TABLE oidc_authorization_codes ADD COLUMN session_version INTEGER;
ALTER TABLE oidc_authorization_codes ADD COLUMN session_exp INTEGER;
