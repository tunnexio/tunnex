-- S10.3 Slice 5: per-cluster DNS. dns_zone is the CUSTOMER'S zone (F6-like, supplied at registration); the
-- resolvable FQDN is <service>.<namespace>.svc.<cluster-name>.<dns_zone> and the client forwards
-- <cluster-name>.<dns_zone> -> the reserved DNS VIP (dns_vip) over the tunnel, where the gateway answers
-- from its exposed-Service VIP map (direct-answer, A1). dns_vip is RESERVED at RegisterCluster (allocated
-- with the range, convention .2 — .1 is conventionally a gateway) so ExposeService can never hand it out.
ALTER TABLE k8s_clusters ADD COLUMN dns_zone text NOT NULL DEFAULT '';
ALTER TABLE k8s_clusters ADD COLUMN dns_vip inet;
