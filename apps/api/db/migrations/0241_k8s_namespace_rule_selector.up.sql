-- K8N-4 slice B: a namespace rule may carry a label selector, and the gateway's Service report
-- (version 2) carries each Service's labels so the control plane can match it.

-- Labels are kept BESIDE the immutable snapshot, one row per reported Service of a version 2 report.
-- A Service with no row here has UNKNOWN labels (a version 1 report): a selector never matches it and
-- never reads it as "does not match". The snapshot tables themselves are unchanged.
CREATE TABLE k8s_service_inventory_item_labels (
    report_id     uuid    NOT NULL,
    inventory_ref uuid    NOT NULL,
    labels        jsonb   NOT NULL DEFAULT '{}',
    -- true = the Service has more labels than the report carries (32 labels / 2048 bytes).
    truncated     boolean NOT NULL DEFAULT false,
    PRIMARY KEY (report_id, inventory_ref),
    FOREIGN KEY (report_id, inventory_ref)
        REFERENCES k8s_service_inventory_items (report_id, inventory_ref) ON DELETE CASCADE,
    CONSTRAINT k8s_service_inventory_item_labels_object CHECK (
        jsonb_typeof(labels) = 'object' AND octet_length(labels::text) <= 8192
    )
);

-- The selector: key=value pairs, all of which must equal the Service's labels. '{}' = the whole
-- namespace, as before. The API validates label syntax and the 8-pair bound.
ALTER TABLE k8s_namespace_exposure_rules
    ADD COLUMN selector jsonb NOT NULL DEFAULT '{}',
    ADD CONSTRAINT k8s_namespace_exposure_rules_selector CHECK (
        jsonb_typeof(selector) = 'object' AND octet_length(selector::text) <= 4096
    );

ALTER TABLE k8s_namespace_exposure_rules DROP CONSTRAINT k8s_namespace_exposure_rules_status;
ALTER TABLE k8s_namespace_exposure_rules ADD CONSTRAINT k8s_namespace_exposure_rules_status CHECK (status IN (
    'pending', 'applied', 'inventory_stale', 'inventory_unavailable',
    'vip_range_exhausted', 'scope_review_limit', 'withdrawal_blocked', 'error',
    'gateway_too_old', 'labels_incomplete'
));
