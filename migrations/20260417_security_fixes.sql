-- Encrypt private keys at rest: add nonce column for AES-256-GCM
-- NULL nonce = legacy plaintext key (will be re-encrypted on first use)
ALTER TABLE keys ADD COLUMN key_nonce BLOB;

-- Per-user access token revocation: reject any access token where iat <= revoked_before
CREATE TABLE IF NOT EXISTS user_access_revocations (
    user_id BLOB PRIMARY KEY NOT NULL,
    revoked_before INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
