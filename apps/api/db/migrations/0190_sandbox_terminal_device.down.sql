-- Dropping a live pin would widen SSH on an old compiler. Require physical
-- cleanup/tombstones first, rather than silently discarding that boundary.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM sandboxes WHERE terminal_device_id IS NOT NULL AND observed_state<>'deleted') THEN
  RAISE EXCEPTION 'complete pinned sandbox cleanup before downgrade';
 END IF;
END $$;
CREATE OR REPLACE FUNCTION sandbox_runtime_binding_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-'runtime_id') IS DISTINCT FROM (to_jsonb(OLD)-'runtime_id')
 OR (OLD.runtime_id IS NOT NULL AND NEW.runtime_id IS DISTINCT FROM OLD.runtime_id) THEN
  RAISE EXCEPTION 'sandbox provider binding is immutable';
 END IF;
 RETURN NEW;
END $$;

ALTER TABLE sandbox_runtime_bindings DROP COLUMN worker_retired_at;
DROP TRIGGER sandbox_terminal_device_immutable ON sandboxes;
DROP FUNCTION sandbox_terminal_device_immutable();
ALTER TABLE sandboxes DROP COLUMN terminal_device_id;
