CREATE TABLE app_passwords (
    id BLOB PRIMARY KEY NOT NULL,
    user_id BLOB NOT NULL,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_app_passwords_user_id ON app_passwords(user_id);

INSERT OR IGNORE INTO settings (key, value) VALUES
    ('ldap_enabled',               'false'),
    ('ldap_base_dn',               'dc=authere,dc=local'),
    ('ldap_bind_address',          '0.0.0.0:3389'),
    ('ldap_service_password_hash', ''),
    ('ldap_password_mode',         'primary_and_app');
