-- S7.5.2: a first-class, NAMED system/service actor for audit rows that no human initiated
-- (e.g. idp-sync deprovisioning a user disabled in the directory). Not NULL, not a borrowed
-- admin id — a legible actor a compliance reader can attribute the action to.
ALTER TABLE audit_logs ADD COLUMN actor_system text NULL;

-- At most one attributed actor KIND: an event is either human-initiated (actor_user_id) or
-- system-initiated (actor_system), never both. A row with neither is a legacy/unattributed
-- event (still allowed). This keeps "who did this" unambiguous.
ALTER TABLE audit_logs ADD CONSTRAINT audit_logs_actor_kind
    CHECK (actor_user_id IS NULL OR actor_system IS NULL);
