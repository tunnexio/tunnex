-- Require an explicit return to restricted mode before removing the setting.
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM beam_policies WHERE open_for_all_users) THEN
  RAISE EXCEPTION 'Return Beam policies to restricted mode before downgrade';
 END IF;
END $$;
ALTER TABLE beam_policies DROP COLUMN open_for_all_users;
