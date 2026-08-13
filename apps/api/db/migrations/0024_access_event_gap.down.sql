ALTER TABLE access_events DROP CONSTRAINT access_events_decision_check;
ALTER TABLE access_events ADD CONSTRAINT access_events_decision_check
    CHECK (decision IN ('allow', 'deny', 'deny_aggregate', 'terminated'));
