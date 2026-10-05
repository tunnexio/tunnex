CREATE OR REPLACE FUNCTION sandbox_require_enforcing_mode() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM organizations WHERE id=NEW.org_id AND zero_trust_mode='enforcing' AND sandboxes_enabled) THEN
  RAISE EXCEPTION 'sandbox creation requires enforcing policy and opt-in';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER sandbox_qualification_trial_immutable ON sandbox_runner_qualification_trials;
DROP FUNCTION sandbox_qualification_trial_immutable();
DROP FUNCTION sandbox_qualification_trial_authority(uuid);
DROP FUNCTION sandbox_qualification_trial_valid(uuid);
DROP FUNCTION sandbox_qualification_trial_grant_valid(uuid);
DROP TABLE sandbox_runner_qualification_events;
DROP FUNCTION sandbox_qualification_event_immutable();
DROP TABLE sandbox_runner_qualification_trials;
