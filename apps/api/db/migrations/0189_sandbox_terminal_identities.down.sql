DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM sandbox_terminal_identities) THEN
  RAISE EXCEPTION 'sandbox terminal identities require deliberate cleanup before downgrade';
 END IF;
END $$;
DROP TABLE sandbox_terminal_identities;
DROP FUNCTION sandbox_terminal_identity_immutable();
