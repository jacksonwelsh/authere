-- Outbound provisioning: Authere pushes user lifecycle events to downstream services over
-- SCIM 2.0. `provisioning_targets` holds the downstream endpoints and their encrypted bearer
-- tokens; `outbound_jobs` is the durable at-least-once queue of pending pushes.
CREATE TABLE IF NOT EXISTS provisioning_targets (
    id BLOB PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    base_url TEXT NOT NULL,
    auth_token_ciphertext BLOB NOT NULL,
    auth_token_nonce BLOB NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    created_by BLOB,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_provisioning_targets_enabled
    ON provisioning_targets(enabled);

-- One row per (event, target). `payload` is a JSON snapshot of the SCIM User at enqueue time
-- so the worker never needs the live DB to construct an outbound body. `external_resource_id`
-- is the target's assigned id (filled in after the first successful create) so later
-- update/delete calls can hit the right path.
CREATE TABLE IF NOT EXISTS outbound_jobs (
    id BLOB PRIMARY KEY NOT NULL,
    target_id BLOB NOT NULL,
    user_id BLOB NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    last_error TEXT,
    last_response_status INTEGER,
    external_resource_id TEXT,
    idempotency_key TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY(target_id) REFERENCES provisioning_targets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_outbound_jobs_ready
    ON outbound_jobs(status, next_attempt_at);

CREATE INDEX IF NOT EXISTS idx_outbound_jobs_user_target
    ON outbound_jobs(target_id, user_id, created_at);
