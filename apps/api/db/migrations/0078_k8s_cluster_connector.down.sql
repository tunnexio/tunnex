DROP INDEX IF EXISTS k8s_clusters_connector_node_unique;
ALTER TABLE k8s_clusters DROP COLUMN connector_node_id;
