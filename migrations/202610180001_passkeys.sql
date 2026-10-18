CREATE TABLE passkeys (
    id BLOB PRIMARY KEY NOT NULL,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BLOB UNIQUE NOT NULL,
    name TEXT NOT NULL,
    credential TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE INDEX passkeys_user_id ON passkeys(user_id);

-- Verification state stays on the server. The opaque challenge ID is carried
-- in an HttpOnly host-only cookie, never accepted from a request body.
CREATE TABLE passkey_challenges (
    id TEXT PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('register', 'login')),
    user_id BLOB REFERENCES users(id) ON DELETE CASCADE,
    token_version INTEGER,
    name TEXT,
    state TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX passkey_challenges_expiry ON passkey_challenges(expires_at);
