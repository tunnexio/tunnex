DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM sandbox_launch_operations) THEN
  RAISE EXCEPTION 'sandbox launch operations require deliberate cleanup before downgrade';
 END IF;
END $$;
DROP TABLE sandbox_launch_operations;
DROP FUNCTION sandbox_launch_operation_binding();
