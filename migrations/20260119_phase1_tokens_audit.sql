-- Refresh tokens for session management
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id BLOB PRIMARY KEY NOT NULL,
    user_id BLOB NOT NULL,
    token_hash TEXT NOT NULL,  -- SHA256 of the refresh token
    expires_at INTEGER NOT NULL,  -- Unix timestamp
    created_at INTEGER NOT NULL,  -- Unix timestamp
    revoked_at INTEGER,  -- Unix timestamp, NULL if not revoked
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);

-- Audit log for security events
CREATE TABLE IF NOT EXISTS audit_log (
    id BLOB PRIMARY KEY NOT NULL,
    timestamp INTEGER NOT NULL,  -- Unix timestamp
    event_type TEXT NOT NULL,  -- 'login_success', 'login_failed', 'logout', 'token_refresh', etc.
    user_id BLOB,  -- NULL for failed logins with unknown user
    actor_id BLOB,  -- Who performed the action (NULL for self-service)
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,  -- JSON with event-specific data
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY(actor_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);

-- Roles table for RBAC (Phase 2, but adding now for init-admin)
CREATE TABLE IF NOT EXISTS roles (
    id BLOB PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id BLOB NOT NULL,
    role_id BLOB NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- Insert default roles
INSERT OR IGNORE INTO roles (id, name, description) VALUES
    (X'0191f9b0a0b07a8f9c4d5e6f7a8b9c0d', 'admin', 'Full administrative access'),
    (X'0191f9b0a0b07a8f9c4d5e6f7a8b9c0e', 'user', 'Standard user access');
