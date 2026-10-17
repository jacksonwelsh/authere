-- Only one callback may redeem a forward login, even across concurrent requests.
CREATE TABLE forward_handoffs (
    id TEXT PRIMARY KEY NOT NULL,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);
CREATE INDEX idx_forward_handoffs_expiry ON forward_handoffs(expires_at);
