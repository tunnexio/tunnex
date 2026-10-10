-- A pending cleanup may have succeeded natively while its ACK was lost. Keep
-- that exact current delivery available for idempotent retry before deletion.
CREATE FUNCTION ipsec_pending_cleanup_delete_guard() RETURNS trigger AS $$
BEGIN
 IF OLD.desired_intent='disabled' AND NEW.desired_intent='deleted'
  AND EXISTS(SELECT 1 FROM ipsec_runtime_state WHERE connection_id=OLD.id AND current_cleanup_id IS NOT NULL)
 THEN RAISE EXCEPTION 'IPsec cleanup in progress' USING ERRCODE='23514',CONSTRAINT='ipsec_runtime_cleanup_pending'; END IF;
 RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_pending_cleanup_delete_guard BEFORE UPDATE ON ipsec_connections FOR EACH ROW EXECUTE FUNCTION ipsec_pending_cleanup_delete_guard();
