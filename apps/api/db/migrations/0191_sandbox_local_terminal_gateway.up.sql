-- A construction proof for new inbound-only, operator-pinned local terminals.
-- Legacy records remain NULL: no historical enforcement scope is inferred.
ALTER TABLE sandboxes ADD COLUMN local_terminal_gateway_id uuid;
ALTER TABLE sandboxes ADD CONSTRAINT sandbox_local_terminal_gateway_same_org
 FOREIGN KEY(org_id,local_terminal_gateway_id) REFERENCES nodes(org_id,id);
ALTER TABLE sandboxes ADD CONSTRAINT sandbox_local_terminal_only
 CHECK(local_terminal_gateway_id IS NULL OR (terminal_device_id IS NOT NULL AND requested_scope='[]'::jsonb));
CREATE OR REPLACE FUNCTION sandbox_terminal_device_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.terminal_device_id IS DISTINCT FROM OLD.terminal_device_id
 OR NEW.local_terminal_gateway_id IS DISTINCT FROM OLD.local_terminal_gateway_id THEN
  RAISE EXCEPTION 'sandbox terminal binding is immutable';
 END IF;
 RETURN NEW;
END $$;
