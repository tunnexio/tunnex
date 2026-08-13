-- S7.5.1: flow / access events — the VISIBILITY half of Zero Trust (who reached what,
-- what was blocked). This is the PG HOT-WINDOW (D4): a bounded, queryable cache for the
-- dashboard + keyset pull-API. The append-only JSONL stream (written alongside) is the
-- SIEM source-of-truth and the retention record; PG is swept to a small window so a POC
-- never fills the customer's disk (D3).
--
-- HISTORICAL-RECORD, not referential: an event records what happened, so it must SURVIVE
-- deletion of the rule/device/resource it names (a deny logged AFTER a rule delete is the
-- whole point). Hence only org_id is a foreign key (tenant scoping + cascade on org
-- delete); rule_id / device / user / resource / group / node are PLAIN uuids preserved
-- verbatim. NOT audit_logs-class (that is low-volume append-only per-mutation; flows are
-- high-cardinality and rotated).
CREATE TABLE access_events (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    -- Per-org monotonic sequence (mirrors the JSONL stream's tamper-evidence seq) so a
    -- gap in the queryable window is detectable, and PG<->JSONL rows cross-reference.
    seq             bigint NOT NULL,
    node_id         uuid,                 -- observing gateway (plain uuid: survives node revoke)
    occurred_at     timestamptz NOT NULL, -- when the gateway observed the flow (agent clock)
    decision        text NOT NULL CHECK (decision IN ('allow', 'deny', 'deny_aggregate', 'terminated')),
    rule_id         uuid,                 -- the grant that matched (NULL = default-deny / no rule)
    src_device_id   uuid,                 -- enriched CP-side (NULL if unresolved)
    src_user_id     uuid,                 -- enriched
    src_ip          text NOT NULL,
    dst_ip          text NOT NULL,
    dst_resource_id uuid,                 -- enriched
    dst_group_id    uuid,                 -- enriched
    protocol        text NOT NULL DEFAULT 'any',
    dst_port        integer,              -- NULL = n/a (protocol=any / L3)
    deny_count      integer NOT NULL DEFAULT 1,  -- >1 for a per-source deny aggregate (port-scan collapse)
    window_end      timestamptz,          -- deny_aggregate: end of the collapse window
    created_at      timestamptz NOT NULL DEFAULT now()  -- CP INGEST time — the RETENTION/sweep clock
);

-- Keyset feed: newest-first, (created_at, id) DESC cursor tuple, scoped by org.
CREATE INDEX access_events_org_created_id_idx ON access_events (org_id, created_at DESC, id DESC);
-- Deny-focused filter (the security money path) reuses the org+created ordering.
CREATE INDEX access_events_org_decision_created_idx ON access_events (org_id, decision, created_at DESC, id DESC);
-- Retention sweep by ingest age (global, cross-org housekeeping).
CREATE INDEX access_events_created_at_idx ON access_events (created_at);
-- Per-org seq lookup (gap detection / dedup of a replayed ingest).
CREATE UNIQUE INDEX access_events_org_seq_key ON access_events (org_id, seq);
