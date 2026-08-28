-- S20.4 provider-first enrollment: optional presentation metadata only. Old
-- callers and existing rows remain unknown; no value is inferred from names,
-- networks, sites, connectors, or endpoints.
ALTER TABLE k8s_clusters
    ADD COLUMN provider text NOT NULL DEFAULT 'unknown',
    ADD COLUMN platform text NOT NULL DEFAULT 'unknown';

ALTER TABLE k8s_clusters
    ADD CONSTRAINT k8s_clusters_provider_platform_pair_check CHECK (
        (provider='unknown' AND platform='unknown')
        OR (provider='aws' AND platform='eks')
        OR (provider='azure' AND platform='aks')
        OR (provider='gcp' AND platform='gke_standard')
        OR (provider='self_managed' AND platform='kubernetes')
    );
