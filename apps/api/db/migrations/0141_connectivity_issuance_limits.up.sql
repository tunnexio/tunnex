-- One serialization row and a bounded rolling-minute issuance ledger per org.
-- Credentials are never stored here. Organization deletion removes the ledger.
CREATE TABLE connectivity_issuance_locks (
    org_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE TABLE connectivity_issuances (
    session_id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    owner_id uuid NOT NULL,
    device_id uuid NOT NULL,
    issued_at timestamptz NOT NULL
);
CREATE INDEX connectivity_issuances_org_time ON connectivity_issuances(org_id, issued_at);
