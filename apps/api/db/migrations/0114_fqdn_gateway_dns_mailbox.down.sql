DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM fqdn_gateway_dns_requests) THEN
        RAISE EXCEPTION 'cannot roll back 0114: durable FQDN gateway DNS mailbox rows exist';
    END IF;
END $$;

DROP TABLE fqdn_gateway_dns_requests;
