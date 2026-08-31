# Leg 2 failed-candidate disposition — 2026-08-31

This record is evidence of a **failed qualification attempt**, not a passing
walk leg.

- Source candidate: `f98e6fb91664ff1e600879f889fc9c29e8210ac0`
- Cluster: `tunnex-aks-ha-walk` / node pool `s205pool`
- Release: `tunnex-s205/s205-gw-a`
- Terminal Helm state: revision 1 `pending-install`
- Gateway Pod: stopped in `host-posture-check`; the main gateway container
  never started
- Control-plane enrollment: no node named `s205-aks-gateway-a` was created
- Exact manager refusal: `WireGuard ownership marker is missing or ambiguous`
- Kernel readback: `wg0`, kind `wireguard`, positive ifindex, empty alias
- Journal readback: schema v1, epoch 1, `preparing`, no recorded ifindex, one
  live owner

The evidence rules out a legacy interface: the clean baseline and preparing
journal preceded this candidate's link creation. The Linux kernel accepted the
`RTM_NEWLINK` request but did not retain the supplied `IFLA_IFALIAS`, so the
manager correctly refused to adopt or configure the ambiguous interface.

The failed release was removed using the product's exact typed
`tunnex k8s abort-install` lifecycle command. It removed the release, workload,
bootstrap Secret, and lifecycle anchor, finalized the control-plane abort, and
intentionally retained the PVC. No Secret, PVC, CNI, sysctl, nftables, route,
WireGuard, journal, or source hot-patch was used.

Because this is an unreleased disposable qualification cluster, Azure reimaged
only VMSS instance `0` of `aks-s205pool-10211578-vmss`. Post-reset proof:

- Azure provisioning succeeded and the VM is running
- both AKS nodes are Ready
- both `tunnex-host-posture` Pods are Ready
- node `aks-s205pool-10211578-vmss000000` reports no `wg0`
- its node-local host-posture journal is absent and no `tnx<12-hex>` staging
  interface is present
- the demo Deployment, Pod, and ClusterIP Service are healthy

The next Leg 2 attempt must use a new clean committed candidate implementing
the approved journalled staged-link transaction. This failed attempt earns no
Leg 2 credit.
