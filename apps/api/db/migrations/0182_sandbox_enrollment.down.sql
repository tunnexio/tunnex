DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM sandbox_bootstrap_tokens) OR EXISTS(SELECT 1 FROM sandbox_runtime_credentials) THEN
  RAISE EXCEPTION 'sandbox enrollment state must be cleaned before downgrade';
 END IF;
END $$;
DROP TABLE sandbox_runtime_credentials;
DROP FUNCTION sandbox_runtime_binding();
DROP TABLE sandbox_bootstrap_tokens;
