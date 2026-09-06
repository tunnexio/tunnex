# Leg 2 failed-candidate disposition — `8911023f`

This is evidence of a **failed qualification attempt**, not a passing walk leg.

- Source candidate: `8911023fd74e08dc7e585305516f92d37709e3ca`
- Candidate version:
  `0.0.0-walk.sha8911023fd74e08dc7e585305516f92d37709e3ca`
- Cluster/release: `tunnex-aks-ha-walk` / `tunnex-s205/s205-gw-a`
- Exact node/image: `aks-s205pool-10211578-vmss000000` /
  `sha256:9b658bba5ee244037e9a811b59b4ff5de28a9cda08c4c83e1966290672008816`
- Gateway and host-posture chart archive SHA-256:
  `dec79f4d67cb27bfb6d9aa39bd4655e6f2d63756545a00a5054221eca546f849`
  and
  `45ffd53320e913b2c5ea9b67f91cf9925f951dbbb683c1be111b8c8ecfafb784`

The redacted `tunnex k8s plan` completed before mutation and bound the clean
organization, static IP `20.115.124.74`, node selector, `managed-csi` storage,
the digest-pinned image, and exact privately published OCI charts. The install
then reached the bounded Helm deadline with the gateway held in its
`host-posture-check` init container. The main gateway container never started
and the lifecycle CLI did not report readiness.

## Exact refusal and staged-link proof

The node manager refused with:

```text
prepare owned host artifacts: nft owner chain contains an unrecognized rule
```

Read-only live `nft -a list chain` showed that the only IPv4 rule was the exact
Tunnex marker. The structural chain declaration also carried a handle:

```text
table ip tunnex {
        chain tunnex_posture_owner { # handle 1
                counter packets 0 bytes 0 comment "tunnex_host_posture_v1" # handle 2
        }
}
```

The candidate's staged WireGuard transaction itself reached the intended
identity-preserving result before the nft readback refusal:

- journal schema `2`, epoch `1`, durable journal state `preparing`;
- staging identity `tnx8a7b6dc8198c`, staging ifindex `22`;
- WireGuard phase `committed` with final name `wg0`, exact Tunnex alias, and the
  same ifindex `22`;
- no gateway owner remained after lifecycle abort;
- heartbeat correctly stayed `blocked` instead of asserting readiness.

The defect was therefore the validator treating the structural chain handle as
an executable foreign rule. It was not an Azure, AKS, CNI, WireGuard staging,
or control-plane enrollment failure.

## Supported recovery and clean reset

After the bounded install exited terminally, the exact typed
`tunnex k8s abort-install` command reconciled the pending Helm release,
Deployment, Pod, Service, bootstrap Secret, lifecycle anchor, and control-plane
claim to absence while deliberately retaining the PVC. The exact typed
`tunnex k8s purge-state` command then permanently deleted only
`s205-gw-a-tunnex-gateway-state`. The namespace returned to only `acr-pull` and
the Kubernetes root-CA ConfigMap.

No nft rule, WireGuard link, journal, sysctl, CNI object, Secret, PVC, or source
was repaired in place. Azure reimaged only disposable VMSS instance `0` of
`aks-s205pool-10211578-vmss`. Azure then reported provisioning `succeeded` and
power `running`; Kubernetes reported the exact node `Ready`. Post-reset
readback proved:

- no journal file (only the manager heartbeat and lock);
- no final `wg0` or `tnx<12-hex>` staging link;
- no IPv4 or IPv6 Tunnex nft table;
- heartbeat `idle` with no owner or refusal reason.

The second node was also idle and the cluster had zero gateway releases and
zero gateway Pods, so the failed-candidate shared-manager Helm release was
removed as fixture teardown. This reset earns no Leg 2 credit. The next attempt
must use a new clean committed candidate containing the provider-neutral D11b
structural-handle parser and must pass the full leg without a repair command.
