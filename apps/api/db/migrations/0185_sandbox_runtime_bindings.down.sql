DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM sandbox_runtime_bindings) THEN
  RAISE EXCEPTION 'sandbox runtime bindings require deliberate cleanup before downgrade';
 END IF;
END $$;
DROP TABLE sandbox_runtime_bindings;
DROP FUNCTION sandbox_runtime_binding_immutable();
