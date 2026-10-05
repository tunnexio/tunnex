-- Optional operator-bound terminal source, immutable after create. NULL retains
-- normal creator-human behavior; a bounded qualification pins one human device.
ALTER TABLE sandboxes ADD COLUMN terminal_device_id uuid;
ALTER TABLE sandboxes ADD CONSTRAINT sandbox_terminal_same_org
 FOREIGN KEY(org_id,terminal_device_id) REFERENCES devices(org_id,id);
CREATE FUNCTION sandbox_terminal_device_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.terminal_device_id IS DISTINCT FROM OLD.terminal_device_id THEN
  RAISE EXCEPTION 'sandbox terminal source is immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sandbox_terminal_device_immutable BEFORE UPDATE ON sandboxes
 FOR EACH ROW EXECUTE FUNCTION sandbox_terminal_device_immutable();

-- The API records the worker's durable retirement receipt only after its own
-- sandbox tombstone. This is not workload telemetry or a browser field.
ALTER TABLE sandbox_runtime_bindings ADD COLUMN worker_retired_at timestamptz;

CREATE OR REPLACE FUNCTION sandbox_runtime_binding_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-'runtime_id'-'worker_retired_at') IS DISTINCT FROM (to_jsonb(OLD)-'runtime_id'-'worker_retired_at')
 OR (OLD.runtime_id IS NOT NULL AND NEW.runtime_id IS DISTINCT FROM OLD.runtime_id)
 OR (OLD.worker_retired_at IS NOT NULL AND NEW.worker_retired_at IS DISTINCT FROM OLD.worker_retired_at) THEN
  RAISE EXCEPTION 'sandbox provider binding is immutable';
 END IF;
 IF NEW.worker_retired_at IS NOT NULL AND OLD.worker_retired_at IS NULL THEN
  IF NOT EXISTS(SELECT 1 FROM sandboxes WHERE id=NEW.sandbox_id AND org_id=NEW.org_id AND desired_state='deleted' AND observed_state='deleted') THEN
   RAISE EXCEPTION 'worker retirement requires a cleanup tombstone';
  END IF;
 END IF;
 RETURN NEW;
END $$;
