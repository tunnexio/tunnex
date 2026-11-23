-- K8N-4 slice A: a namespace rule can leave named Services out. The rule never exposes an excluded
-- Service and withdraws the exposures it made for one. Names only: no patterns, at most 100.
ALTER TABLE k8s_namespace_exposure_rules
    ADD COLUMN excluded_services text[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT k8s_namespace_exposure_rules_excluded_services CHECK (
        cardinality(excluded_services) <= 100
        AND array_ndims(excluded_services) IS NOT DISTINCT FROM CASE WHEN cardinality(excluded_services) = 0 THEN NULL ELSE 1 END
        AND array_position(excluded_services, NULL) IS NULL
        AND array_to_string(excluded_services, '') !~ '[^-a-z0-9]'
        AND array_to_string(excluded_services, ',') ~ '^([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(,|$))*$'
    );
