DO $$ BEGIN IF EXISTS(SELECT 1 FROM beam_shares WHERE state IN ('starting','active','paused') AND expires_at>now()) THEN RAISE EXCEPTION 'Drain Beam shares before downgrade'; END IF; END $$;
DROP TABLE beam_streams,beam_browser_sessions,beam_launch_codes,beam_pending_launches,beam_grants,beam_shares,beam_policies;
