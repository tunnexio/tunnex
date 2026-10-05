CREATE TABLE sandbox_terminal_identities (
 sandbox_id uuid PRIMARY KEY,
 org_id uuid NOT NULL,
 host_public_key text NOT NULL CHECK(length(host_public_key) BETWEEN 32 AND 8192),
 host_key_fingerprint text NOT NULL CHECK(host_key_fingerprint LIKE 'SHA256:%'),
 FOREIGN KEY(org_id,sandbox_id) REFERENCES sandboxes(org_id,id) ON DELETE CASCADE
);
CREATE FUNCTION sandbox_terminal_identity_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'sandbox terminal identity is immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sandbox_terminal_identity_immutable BEFORE UPDATE ON sandbox_terminal_identities FOR EACH ROW EXECUTE FUNCTION sandbox_terminal_identity_immutable();
