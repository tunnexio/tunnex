-- Refuse destructive rollback once archives/jobs or expanded policies exist.
-- Dropping the snapshot/manifest state could destroy access to sole archived
-- payloads; clamping an administrator's policy would silently alter retention.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM server_access_recordings WHERE archive_status<>'none' OR archive_storage_sealed IS NOT NULL)
    OR EXISTS(SELECT 1 FROM server_access_settings WHERE recording_retention_days>30 OR archive_storage_sealed IS NOT NULL OR archive_enabled) THEN
  RAISE EXCEPTION 'server access archive rollback requires explicit preservation of archive jobs, configuration and expanded retention policies';
 END IF;
END $$;
DROP INDEX server_access_recording_archive_jobs;
ALTER TABLE server_access_recordings
 DROP COLUMN archive_digest,
 DROP CONSTRAINT server_access_recordings_status_check,
 ADD CONSTRAINT server_access_recordings_status_check CHECK(status IN ('capturing','available','incomplete','failed','expired')),
 DROP COLUMN archive_error, DROP COLUMN archive_retry_after,
 DROP COLUMN archived_at, DROP COLUMN archive_requested_at,
 DROP COLUMN archive_incomplete, DROP COLUMN archive_manifest_verified, DROP COLUMN archive_next_seq,
 DROP COLUMN archive_status, DROP COLUMN archive_storage_sealed,
 ALTER COLUMN expires_at SET DEFAULT now()+interval '7 days';
ALTER TABLE server_access_settings
 DROP COLUMN archive_enabled, DROP COLUMN archive_storage_sealed,
 DROP CONSTRAINT server_access_settings_recording_retention_days_check,
 ADD CONSTRAINT server_access_settings_recording_retention_days_check CHECK(recording_retention_days BETWEEN 1 AND 30),
 ALTER COLUMN recording_retention_days SET DEFAULT 7;
