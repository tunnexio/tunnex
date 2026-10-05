-- Stable encrypted worker handoff, separate from human inventory and logs.
CREATE TABLE sandbox_launch_operations (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL,
 sandbox_id uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation>0),
 gateway_node_id uuid NOT NULL,
 runtime_id text NOT NULL CHECK(runtime_id ~ '^[a-f0-9]{64}$'),
 spec_hash text NOT NULL CHECK(spec_hash ~ '^[a-f0-9]{64}$'),
 bootstrap_token_id uuid NOT NULL UNIQUE REFERENCES sandbox_bootstrap_tokens(id),
 handoff_ciphertext text,
 created_at timestamptz NOT NULL DEFAULT now(),
 confirmed_at timestamptz,
 UNIQUE(sandbox_id,generation),
 FOREIGN KEY(org_id,sandbox_id) REFERENCES sandboxes(org_id,id),
 FOREIGN KEY(org_id,gateway_node_id) REFERENCES nodes(org_id,id),
 CHECK((handoff_ciphertext IS NULL)=(confirmed_at IS NOT NULL))
);
CREATE FUNCTION sandbox_launch_operation_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-'handoff_ciphertext'-'confirmed_at') IS DISTINCT FROM (to_jsonb(OLD)-'handoff_ciphertext'-'confirmed_at')
  OR (OLD.confirmed_at IS NOT NULL AND NEW IS DISTINCT FROM OLD)
  OR (NEW.handoff_ciphertext IS DISTINCT FROM OLD.handoff_ciphertext AND NEW.handoff_ciphertext IS NOT NULL) THEN
   RAISE EXCEPTION 'sandbox launch operation binding is immutable';
  END IF;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM sandbox_bootstrap_tokens t JOIN sandbox_runtime_bindings r ON r.sandbox_id=t.sandbox_id AND r.org_id=t.org_id
   WHERE t.id=NEW.bootstrap_token_id AND t.org_id=NEW.org_id AND t.sandbox_id=NEW.sandbox_id AND t.generation=NEW.generation
   AND t.gateway_node_id=NEW.gateway_node_id AND r.runtime_id=NEW.runtime_id AND r.spec_hash=NEW.spec_hash) THEN
  RAISE EXCEPTION 'sandbox launch requires matching token and provider binding';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sandbox_launch_operation_binding BEFORE INSERT OR UPDATE ON sandbox_launch_operations FOR EACH ROW EXECUTE FUNCTION sandbox_launch_operation_binding();
