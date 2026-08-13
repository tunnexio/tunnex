-- S10.3a: a Kubernetes cluster is served by one explicit in-cluster connector
-- node.  site_id remains the logical site/ownership boundary; connector_node_id
-- selects the only node allowed to receive the VIP/DNS map and resolve pod
-- endpoints.  Existing rows deliberately remain NULL until an operator binds a
-- connector — guessing amongst same-site gateways would create a dead service.
ALTER TABLE k8s_clusters
    ADD COLUMN connector_node_id uuid REFERENCES nodes (id) ON DELETE SET NULL;

CREATE UNIQUE INDEX k8s_clusters_connector_node_unique
    ON k8s_clusters (connector_node_id)
    WHERE connector_node_id IS NOT NULL;
