-- New policies default to 30 days. Existing explicit settings and recording
-- expires_at values are preserved, including previous seven-day policies.
ALTER TABLE server_access_settings
 DROP CONSTRAINT server_access_settings_recording_retention_days_check,
 ADD CONSTRAINT server_access_settings_recording_retention_days_check CHECK(recording_retention_days BETWEEN 1 AND 3650),
 ALTER COLUMN recording_retention_days SET DEFAULT 30,
 ADD COLUMN archive_storage_sealed bytea,
 ADD COLUMN archive_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE server_access_recordings
 ALTER COLUMN expires_at SET DEFAULT now()+interval '30 days',
 ADD COLUMN archive_storage_sealed bytea,
 ADD COLUMN archive_status text NOT NULL DEFAULT 'none' CHECK(archive_status IN ('none','pending','uploading','available','failed')),
 ADD COLUMN archive_next_seq integer NOT NULL DEFAULT 0 CHECK(archive_next_seq BETWEEN 0 AND 4096),
 ADD COLUMN archive_manifest_verified boolean NOT NULL DEFAULT false,
 ADD COLUMN archive_incomplete boolean NOT NULL DEFAULT false,
 ADD COLUMN archive_requested_at timestamptz,
 ADD COLUMN archived_at timestamptz,
 ADD COLUMN archive_retry_after timestamptz,
 ADD COLUMN archive_error text NOT NULL DEFAULT '',
 ADD COLUMN archive_digest bytea CHECK(archive_digest IS NULL OR octet_length(archive_digest)=32),
 DROP CONSTRAINT server_access_recordings_status_check,
 ADD CONSTRAINT server_access_recordings_status_check CHECK(status IN ('capturing','available','incomplete','failed','expired','archived'));
CREATE INDEX server_access_recording_archive_jobs ON server_access_recordings(archive_retry_after,archive_requested_at) WHERE archive_status IN ('pending','uploading','failed');
