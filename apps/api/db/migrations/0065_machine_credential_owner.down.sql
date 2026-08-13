DROP INDEX IF EXISTS machine_credentials_user_id_idx;
ALTER TABLE machine_credentials DROP COLUMN IF EXISTS user_id;
