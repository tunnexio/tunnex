-- S9.1 D-S9.6-CERT-DELIVERY: the per-gateway OpenVPN SERVER cert, minted once + recorded so the CP can
-- re-deliver the SAME material idempotently on every reconcile (never a fresh mint per tick). Unlike a
-- CLIENT cert (key ephemeral, never stored — D-S9.2-1), the SERVER key is STORED SEALED under the
-- master key (like the agent-CA key), because it must be redeliverable to the gateway over the mTLS
-- control channel. One server cert per gateway.
CREATE TABLE ovpn_server_certs (
    id         uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    node_id    uuid NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    serial     text NOT NULL,
    cert_pem   text NOT NULL,
    sealed_key text NOT NULL,  -- the server private key, SEALED (crypto.Sealer) — never plaintext at rest
    not_after  timestamptz NOT NULL,
    issued_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX ovpn_server_certs_node_key ON ovpn_server_certs (node_id); -- mint-once per gateway
