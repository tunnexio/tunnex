-- K8N-4 slice C: a namespace rule declared by a TunnexNamespaceExposure resource is created with the
-- operator's machine credential and carries it here, the same ownership marker clusters, exposures and
-- access rules have (0053). NULL = made by a person in the dashboard. A machine credential may change or
-- remove only rules that carry a marker; a person may not edit one that does.
-- ON DELETE SET NULL: when the credential is deleted the rule stays and becomes an ordinary dashboard
-- rule, which the operator then no longer touches.
ALTER TABLE k8s_namespace_exposure_rules
    ADD COLUMN managed_by_machine uuid REFERENCES machine_credentials (id) ON DELETE SET NULL;
