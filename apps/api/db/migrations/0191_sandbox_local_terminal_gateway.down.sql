DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM sandboxes WHERE local_terminal_gateway_id IS NOT NULL AND observed_state<>'deleted') THEN
  RAISE EXCEPTION 'cannot discard unfinished sandbox local enforcement proof';
 END IF;
END $$;
CREATE OR REPLACE FUNCTION sandbox_terminal_device_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.terminal_device_id IS DISTINCT FROM OLD.terminal_device_id THEN
  RAISE EXCEPTION 'sandbox terminal source is immutable';
 END IF;
 RETURN NEW;
END $$;
ALTER TABLE sandboxes DROP COLUMN local_terminal_gateway_id;
