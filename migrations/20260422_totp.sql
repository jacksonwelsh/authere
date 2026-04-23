-- Optional TOTP second factor. One row per user who has initiated TOTP enrollment.
-- `activated_at` remains NULL until the user confirms their first code; LDAP and
-- login treat "activated_at IS NOT NULL" as "MFA is enforced for this user".
CREATE TABLE IF NOT EXISTS user_totps (
    user_id BLOB PRIMARY KEY NOT NULL,
    -- AES-GCM(AUTHERE_KEY_SECRET) over the raw 20-byte SHA1 secret.
    -- Stored as "hex(nonce):hex(ciphertext)".
    secret_encrypted TEXT NOT NULL,
    -- Highest TOTP step number ever accepted. Blocks replay within the ±1 step
    -- drift window by requiring strictly greater steps on subsequent verifies.
    last_used_step INTEGER,
    activated_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Single-use recovery codes. Stored as SHA-256 hex; cleartext is shown once at
-- enrollment and never again.
CREATE TABLE IF NOT EXISTS totp_recovery_codes (
    id BLOB PRIMARY KEY NOT NULL,
    user_id BLOB NOT NULL,
    code_hash TEXT NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_totp_recovery_user ON totp_recovery_codes(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_totp_recovery_hash ON totp_recovery_codes(code_hash);
