-- Drop SCIM and outbound-provisioning tables, the SCIM-only `external_id`
-- column on users, and SCIM-only indexes. `active`, `created_at`, and
-- `updated_at` stay; they are used outside of SCIM (auth blocks deactivated
-- users; timestamps are general-purpose).

DROP TABLE IF EXISTS outbound_jobs;
DROP TABLE IF EXISTS provisioning_targets;
DROP TABLE IF EXISTS scim_tokens;

-- Indexes referencing dropped columns or removed lookup paths.
DROP INDEX IF EXISTS idx_users_external_id;
DROP INDEX IF EXISTS idx_users_username_lower;
DROP INDEX IF EXISTS idx_users_email_lower;

ALTER TABLE users DROP COLUMN external_id;
