DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM k8s_clusters WHERE provider <> 'unknown' OR platform <> 'unknown') THEN
        RAISE EXCEPTION '0122 rollback refused: Kubernetes provider metadata exists';
    END IF;
END;
$$;

ALTER TABLE k8s_clusters DROP CONSTRAINT k8s_clusters_provider_platform_pair_check;
ALTER TABLE k8s_clusters DROP COLUMN platform;
ALTER TABLE k8s_clusters DROP COLUMN provider;
