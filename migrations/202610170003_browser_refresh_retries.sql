-- Short-lived encrypted retry responses let concurrent browser tabs rotate the
-- same cookie without interpreting normal parallel requests as token theft.
ALTER TABLE refresh_tokens ADD COLUMN browser_retry_until INTEGER;
ALTER TABLE refresh_tokens ADD COLUMN browser_retry_pair BLOB;
