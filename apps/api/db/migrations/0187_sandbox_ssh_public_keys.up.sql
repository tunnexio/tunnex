ALTER TABLE sandboxes ADD COLUMN ssh_public_keys jsonb NOT NULL DEFAULT '[]'
 CHECK (jsonb_typeof(ssh_public_keys)='array' AND jsonb_array_length(ssh_public_keys)<=7 AND octet_length(ssh_public_keys::text)<=65536);
CREATE FUNCTION sandbox_ssh_keys_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.ssh_public_keys IS DISTINCT FROM OLD.ssh_public_keys THEN
  RAISE EXCEPTION 'sandbox SSH public keys are immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sandbox_ssh_keys_immutable BEFORE UPDATE OF ssh_public_keys ON sandboxes FOR EACH ROW EXECUTE FUNCTION sandbox_ssh_keys_immutable();
