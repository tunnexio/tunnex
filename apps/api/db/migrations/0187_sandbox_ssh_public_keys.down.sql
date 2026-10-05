DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM sandboxes WHERE ssh_public_keys<>'[]'::jsonb) THEN
  RAISE EXCEPTION 'sandbox SSH bindings require deliberate cleanup before downgrade';
 END IF;
END $$;
DROP TRIGGER sandbox_ssh_keys_immutable ON sandboxes;
DROP FUNCTION sandbox_ssh_keys_immutable();
ALTER TABLE sandboxes DROP COLUMN ssh_public_keys;
