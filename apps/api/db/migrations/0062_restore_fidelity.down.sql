ALTER TABLE ovpn_client_certs DROP COLUMN revoked_cause;
ALTER TABLE devices DROP COLUMN provisioned_node_id;
ALTER TABLE devices DROP COLUMN revoked_prev_status;
