-- Revert the field partition: drop the controller's demoted field and rename configured back to members.
-- A non-empty demoted set (an in-flight failover) is LOST on rollback — the active order re-derives from
-- configured alone (single-writer world), which is exactly the pre-reduce behavior.
ALTER TABLE org_hub_set DROP COLUMN demoted;
ALTER TABLE org_hub_set RENAME COLUMN configured TO members;
