# S20.5 Leg 2 failed-candidate record — `3341b66d`

This record is negative evidence only. It does **not** pass Leg 2.

- Source/content tip: `3341b66dd5f702fdbd8faedf65b166ca9612a9fd`.
- Candidate scalar: `0.0.0-walk.sha3341b66dd5f702fdbd8faedf65b166ca`
  (46 characters, within the enrollment API's 50-character limit).
- The separately built node binary contained that exact scalar once and its
  image configuration had no `TUNNEX_AGENT_VERSION` override. Published node
  image: `sha256:43bcd299d47dd0ebdd2eda47c29777635f3d9b3590929a494076cf16bf193e72`.
- The token-free bundle verified locally and on the control-plane host. All
  four private OCI charts pulled back byte-identically. The redacted A plan
  created no gateway object, and its saved SHA-256 was
  `b5a96140795da174289fa54336b69f3cfbca804415658584325ba9aab9e963ca`.
- The one-command A install made the host manager Ready on both nodes, bound
  the requested static public IP, bound a new PVC, passed manager admission,
  and started the exact digest-pinned gateway image.
- Gateway startup then failed closed because live
  `net/ipv4/conf/wg0/rp_filter` retained the node's strict value and the gateway
  container correctly had a read-only `/proc/sys`. The logged failure was
  `WireGuard rp_filter ... could not be applied: ... read-only file system`.
  Startup ownership withdrawal therefore refused and the Deployment never
  became Ready. No manual sysctl, CNI, nftables, route, WireGuard, Secret, PVC,
  chart, or workload repair was attempted.
- `tunnex k8s abort-install` removed the partial Helm release, identity and
  token-blind recovery metadata through the supported path. `tunnex k8s
  purge-state` then permanently removed the retained failed-claim PVC through
  the supported typed path.
- Final readback showed both manager heartbeats `idle` with no owners. The
  affected node's v2 journal was `restored`; both nodes had no `wg0` and no
  Tunnex nft table. The idle singleton manager was then uninstalled normally.

No bootstrap token, machine token, private key, certificate, kubeconfig,
service-account token or lifecycle UUID is stored in this artifact.
