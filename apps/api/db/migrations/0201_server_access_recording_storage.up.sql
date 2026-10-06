-- NULL snapshots preserve existing PostgreSQL recordings and default storage.
ALTER TABLE server_access_settings ADD COLUMN recording_storage_sealed bytea;
ALTER TABLE server_access_recordings ADD COLUMN storage_sealed bytea, ADD COLUMN storage_cleanup_seq integer NOT NULL DEFAULT 0 CHECK(storage_cleanup_seq BETWEEN 0 AND 4097);
