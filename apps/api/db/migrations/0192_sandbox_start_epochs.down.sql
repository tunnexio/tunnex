DO $$BEGIN
 IF EXISTS(SELECT 1 FROM sandbox_start_epochs e JOIN sandboxes s ON s.id=e.sandbox_id WHERE s.observed_state<>'deleted') THEN
  RAISE EXCEPTION 'unfinished resumed sandbox prevents epoch removal';
 END IF;
END$$;
ALTER TABLE sandbox_network_withdrawals DROP COLUMN network_epoch_id;
DROP TABLE sandbox_start_epochs;
DROP FUNCTION sandbox_start_epoch_immutable();
