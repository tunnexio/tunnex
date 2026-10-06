-- Refuse rollback that would silently resurrect retired server identities.
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM server_access_servers WHERE removed_at IS NOT NULL) THEN
  RAISE EXCEPTION 'Cannot rollback server removal while retired identities exist';
 END IF;
END $$;
ALTER TABLE server_access_servers DROP COLUMN removed_at;
