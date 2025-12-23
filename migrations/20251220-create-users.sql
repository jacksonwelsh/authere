CREATE TABLE IF NOT EXISTS users (
    id BLOB PRIMARY KEY NOT NULL,
    username TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    email TEXT
);

CREATE TABLE IF NOT EXISTS authenticators (
    id BLOB PRIMARY KEY NOT NULL,
    -- password or totp
    type TEXT NOT NULL,
    -- for password, the salted hash. for totp, the secret (as str)
    value TEXT NOT NULL,
    owner_id BLOB NOT NULL,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
);
