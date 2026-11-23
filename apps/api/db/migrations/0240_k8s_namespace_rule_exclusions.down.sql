ALTER TABLE k8s_namespace_exposure_rules
    DROP CONSTRAINT IF EXISTS k8s_namespace_exposure_rules_excluded_services,
    DROP COLUMN IF EXISTS excluded_services;
