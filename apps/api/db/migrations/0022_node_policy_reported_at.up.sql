-- S7.4b fold [1]: the timestamp of the last APPLIED-POLICY REPORT (the agent POST that carries
-- the applied hash), stamped by the CP clock at report-ingest ONLY. Distinct from last_seen_at,
-- which is also bumped by DesiredState GET polls + cert renewal — so last_seen can't answer
-- "has the agent stopped REPORTING its applied policy?". The desync freshness gate reads THIS.
-- NULL = never reported (or pre-migration) → treated as STALE / can't-determine, never fresh.
ALTER TABLE nodes ADD COLUMN policy_reported_at timestamptz;
