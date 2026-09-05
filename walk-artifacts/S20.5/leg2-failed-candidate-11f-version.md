# S20.5 Leg 2 failed-candidate record — `11f4fdc3`

This record is negative evidence only. It does **not** pass Leg 2.

- Source/content tip: `11f4fdc32a357303d3c7b08b7648fee23b15c3f8`.
- Candidate scalar: `0.0.0-walk.sha11f4fdc32a357303d3c7b08b7648fee23b15c3f8`
  (54 characters).
- The immutable private OCI charts pulled back byte-identically, the redacted
  plan passed, the cluster-singleton host-posture manager became Ready on both
  AKS nodes, and the gateway init admission plus static public-IP/PVC binding
  succeeded.
- Enrollment then failed closed at the control plane with HTTP 400 because
  `agent_version` exceeds its 50-character OpenAPI maximum. The gateway main
  container never became Ready, so this candidate was rejected rather than
  worked around with a runtime version override or API widening.
- `tunnex k8s abort-install` removed the partial release, bootstrap anchor and
  Secret through the supported lifecycle path. `tunnex k8s purge-state` then
  purged the failed claim's retained state through the supported path.
- Final readback before uninstalling the idle singleton manager showed both
  manager heartbeats `idle` with no owners. The affected node's v2 journal was
  `restored`; both nodes had no final `wg0`, no staging link and no Tunnex nft
  table. Namespace `tunnex-s205` retained only the pre-existing ACR pull Secret.
- The idle `tunnex-host-posture` Helm release was then uninstalled normally.

No bootstrap token, machine token, private key, certificate, kubeconfig,
service-account token or lifecycle UUID is stored in this artifact.
