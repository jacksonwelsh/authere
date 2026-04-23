-- M2: reliability polish + bootstrap sync.
-- `backfill_done_at` marks the epoch when a target's first-time backfill completed, so we
-- only enqueue the initial-sync create jobs once regardless of how many times the target is
-- toggled off/on afterwards.
ALTER TABLE provisioning_targets ADD COLUMN backfill_done_at INTEGER;
