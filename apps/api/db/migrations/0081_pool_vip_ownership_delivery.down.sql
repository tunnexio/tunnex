-- The delivery ledger carries the only durable replay/generation fence. Dropping
-- it with data would permit a stale handoff after rollback, so refuse loudly.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pool_vip_ownership_deliveries)
       OR EXISTS (SELECT 1 FROM pool_vip_ownership_delivery_ack_receipts)
       OR EXISTS (SELECT 1 FROM pool_vip_ownership_delivery_states) THEN
        RAISE EXCEPTION 'cannot roll back 0081: pool VIP ownership delivery ledger contains data';
    END IF;
END;
$$;

DROP TABLE pool_vip_ownership_delivery_ack_receipts;
DROP TABLE pool_vip_ownership_deliveries;
DROP TABLE pool_vip_ownership_delivery_states;
