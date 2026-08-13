-- S7.5.1 (4/n): 'gap' is a first-class access event — a LEGIBLE marker the CP writes when
-- an agent reports dropped events (buffer overflow or kernel nflog overrun). "N events
-- dropped here" is queryable/renderable in both stores, so a hole in the audit trail is
-- visible as a hole, never inferred. deny_count carries N on a gap row.
ALTER TABLE access_events DROP CONSTRAINT access_events_decision_check;
ALTER TABLE access_events ADD CONSTRAINT access_events_decision_check
    CHECK (decision IN ('allow', 'deny', 'deny_aggregate', 'terminated', 'gap'));
