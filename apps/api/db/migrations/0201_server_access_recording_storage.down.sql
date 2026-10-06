-- Do not orphan external ciphertext or erase configured destinations on rollback.
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM server_access_settings WHERE recording_storage_sealed IS NOT NULL)
 OR EXISTS (SELECT 1 FROM server_access_recordings WHERE storage_sealed IS NOT NULL) THEN
  RAISE EXCEPTION 'clear external recording destinations and expire their recordings before rollback';
 END IF;
END $$;
ALTER TABLE server_access_recordings DROP COLUMN storage_sealed, DROP COLUMN storage_cleanup_seq;
ALTER TABLE server_access_settings DROP COLUMN recording_storage_sealed;
