-- M4: dead-letter webhook URL per target. When a job transitions to `dead` the worker
-- fires a best-effort POST to this URL so admins can page on broken integrations.
ALTER TABLE provisioning_targets ADD COLUMN dead_letter_webhook_url TEXT;
