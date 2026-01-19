CREATE TABLE IF NOT EXISTS keys (
    id BLOB PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    public_key BLOB NOT NULL,
    private_key BLOB NOT NULL
);
