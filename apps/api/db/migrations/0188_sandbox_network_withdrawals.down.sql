DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM sandbox_network_withdrawals) THEN
  RAISE EXCEPTION 'sandbox withdrawal receipts require deliberate cleanup before downgrade';
 END IF;
END $$;
DROP TABLE sandbox_network_withdrawals;
