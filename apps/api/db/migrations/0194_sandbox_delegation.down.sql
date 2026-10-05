DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM sandbox_delegations) THEN
 RAISE EXCEPTION 'sandbox delegation state must be explicitly retired before downgrade';
 END IF;
END $$;
DROP FUNCTION sandbox_delegation_valid(uuid);
DROP TABLE sandbox_delegated_instances;
DROP TABLE sandbox_delegations;
ALTER TABLE organizations DROP COLUMN sandbox_delegation_enabled;
