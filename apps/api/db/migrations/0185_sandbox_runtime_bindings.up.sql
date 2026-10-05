-- A provider create may succeed before the worker persists its receipt. Keep
-- immutable expected specification separate from optional observed runtime ID.
CREATE TABLE sandbox_runtime_bindings (
 sandbox_id uuid PRIMARY KEY,
 org_id uuid NOT NULL,
 spec_hash text NOT NULL CHECK(spec_hash ~ '^[a-f0-9]{64}$'),
 image_digest text NOT NULL CHECK(image_digest ~ '^sha256:[a-f0-9]{64}$'),
 memory_mib integer NOT NULL CHECK(memory_mib BETWEEN 64 AND 4096),
 cpus integer NOT NULL CHECK(cpus BETWEEN 1 AND 4),
 pids integer NOT NULL CHECK(pids BETWEEN 16 AND 512),
 runtime_id text CHECK(runtime_id ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(org_id,sandbox_id) REFERENCES sandboxes(org_id,id)
);
CREATE FUNCTION sandbox_runtime_binding_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-'runtime_id') IS DISTINCT FROM (to_jsonb(OLD)-'runtime_id')
 OR (OLD.runtime_id IS NOT NULL AND NEW.runtime_id IS DISTINCT FROM OLD.runtime_id) THEN
  RAISE EXCEPTION 'sandbox provider binding is immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sandbox_runtime_binding_immutable BEFORE UPDATE ON sandbox_runtime_bindings FOR EACH ROW EXECUTE FUNCTION sandbox_runtime_binding_immutable();
