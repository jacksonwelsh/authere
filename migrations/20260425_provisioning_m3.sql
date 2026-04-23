-- M3: per-target attribute mapping. Admins can rename top-level SCIM fields before the
-- outbound request hits a target (e.g. `externalId → external_id` for snake_case peers).
-- Stored as a JSON object of `{"from_key": "to_key"}` strings; NULL = identity.
ALTER TABLE provisioning_targets ADD COLUMN attribute_map TEXT;
