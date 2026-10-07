DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM beam_installation_settings WHERE operator_enabled OR readiness_passed)
 OR EXISTS(SELECT 1 FROM beam_shares WHERE state IN ('starting','active','paused') AND expires_at>now()) THEN
  RAISE EXCEPTION 'Disable installation authority and drain Beam shares before downgrade';
 END IF;
END $$;
DROP TABLE beam_installation_settings;
