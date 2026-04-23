-- Default session (refresh-token) lifetime in seconds. 7 days matches the historical
-- REFRESH_TOKEN_LIFETIME constant so existing deployments see no behavior change.
INSERT OR IGNORE INTO settings (key, value) VALUES ('session_expiry_seconds', '604800');
