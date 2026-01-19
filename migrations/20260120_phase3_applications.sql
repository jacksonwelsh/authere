-- Applications registry for forward auth
CREATE TABLE IF NOT EXISTS applications (
    id BLOB PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,  -- URL-friendly identifier
    host_pattern TEXT,          -- Exact host or regex pattern to match
    path_prefix TEXT,           -- Optional path prefix to match
    required_roles TEXT,        -- JSON array of role names required for access
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_applications_slug ON applications(slug);
CREATE INDEX IF NOT EXISTS idx_applications_enabled ON applications(enabled);
