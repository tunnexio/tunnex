-- A rule with a selector cannot survive without the column: it would become a whole-namespace rule and
-- expose Services nobody opted into. Such rules are removed; their exposures stay as ordinary
-- dashboard exposures (the ownership rows cascade away), which exposes nothing new.
DELETE FROM k8s_namespace_exposure_rules WHERE selector <> '{}'::jsonb;
UPDATE k8s_namespace_exposure_rules SET status = 'error' WHERE status IN ('gateway_too_old', 'labels_incomplete');
ALTER TABLE k8s_namespace_exposure_rules DROP CONSTRAINT IF EXISTS k8s_namespace_exposure_rules_status;
ALTER TABLE k8s_namespace_exposure_rules ADD CONSTRAINT k8s_namespace_exposure_rules_status CHECK (status IN (
    'pending', 'applied', 'inventory_stale', 'inventory_unavailable',
    'vip_range_exhausted', 'scope_review_limit', 'withdrawal_blocked', 'error'
));
ALTER TABLE k8s_namespace_exposure_rules
    DROP CONSTRAINT IF EXISTS k8s_namespace_exposure_rules_selector,
    DROP COLUMN IF EXISTS selector;
DROP TABLE IF EXISTS k8s_service_inventory_item_labels;
