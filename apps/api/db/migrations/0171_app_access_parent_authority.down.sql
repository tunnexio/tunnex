DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM app_access_parent_logout_tombstones) OR EXISTS (SELECT 1 FROM users WHERE app_auth_epoch <> 1) THEN
 RAISE EXCEPTION 'retained app parent authority prevents rollback';
 END IF;
END $$;
DROP TABLE app_access_parent_logout_tombstones;
ALTER TABLE mfa_challenges DROP COLUMN verified_app_auth_epoch;
ALTER TABLE users DROP COLUMN app_auth_epoch;
