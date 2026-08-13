-- S10.3 Slice 4: capture the cluster's Kubernetes SERVICE CIDR at registration — the range K8s assigns
-- ClusterIPs from. The gateway uses it to classify a resolved address WITHOUT the K8s API (the (A)
-- no-API boundary): a resolved IP inside the Service CIDR is a ClusterIP (DNAT it); an IP OUTSIDE it is a
-- pod IP (a headless Service has no stable VIP -> refuse as unexposable). Operator-supplied like the
-- endpoint (F6), the natural companion to the VIP range.
--
-- NOT NULL with the K8s default (10.96.0.0/12) so the column is total; RegisterCluster always sets it
-- explicitly (the default only covers migration of any pre-existing row).
ALTER TABLE k8s_clusters ADD COLUMN service_cidr cidr NOT NULL DEFAULT '10.96.0.0/12';
