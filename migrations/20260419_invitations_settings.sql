CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO settings (key, value) VALUES ('open_registration', 'false');

CREATE TABLE IF NOT EXISTS invitations (
    id          TEXT PRIMARY KEY NOT NULL,
    created_by  BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label       TEXT,
    max_uses    INTEGER,
    uses        INTEGER NOT NULL DEFAULT 0,
    expires_at  INTEGER,
    created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_invitations_created_by ON invitations(created_by);
