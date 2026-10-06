-- Persistent retry scheduling prevents one inaccessible destination from
-- starving retention for other organizations. Keys/configuration stay intact.
ALTER TABLE server_access_recordings ADD COLUMN storage_retry_after timestamptz;
