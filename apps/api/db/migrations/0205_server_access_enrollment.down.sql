DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM server_access_servers WHERE cardinality(accounts)=0) THEN
  RAISE EXCEPTION 'Complete or remove pending-discovery servers before rollback';
 END IF;
 IF EXISTS(SELECT 1 FROM server_access_enrollments WHERE state IN ('preparing','awaiting_authorization','queued','running') AND expires_at>now()) THEN
  RAISE EXCEPTION 'Cancel active server enrollment jobs before rollback';
 END IF;
END $$;
DROP TABLE server_access_enrollments;

ALTER TABLE server_access_servers DROP CONSTRAINT server_access_servers_accounts_check;
ALTER TABLE server_access_servers ADD CONSTRAINT server_access_servers_accounts_check CHECK(cardinality(accounts) BETWEEN 1 AND 16);
