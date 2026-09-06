# AWS direct-Helm PVC guard — bounded metadata proof

Date: 2026-09-06. Chart guard source:
`7616036a62f8cbf5c9acba3a937634002d48a171`.
Helm 3.18.4, existing approved AWS EKS sandbox in ap-south-1; account and exact
cluster checked before mutation. No CP, gateway, node or client image changed.

## Safety boundary

All three workers already hosted working gateways. This test deliberately used
an isolated namespace `tunnex-pvc-guard-20260906-gstqsc` and release `pvc-guard`,
with a unique node selector verified to match zero nodes. Preflight was disabled
and operations used `--no-hooks`, demonstrating that the new guard does not
depend on hooks. Cluster RBAC was disabled; no cluster-scoped permissions added.

An explicitly nonexistent StorageClass kept the PVC Pending with no bound
volume, preventing dynamic EBS allocation. The chart referenced a nonexistent
Secret name only; no join token was minted, supplied or stored. Endpoint used
documentation address 192.0.2.1 and a verified unused NodePort 31971. No public
load balancer or new worker was created. No pod was scheduled or container
started. These settings are a test fixture, not customer installation advice.

## Observations

1. With the named PVC absent, actual `helm install` of the unmodified gateway
   chart succeeded at 11:26 IST, revision 1. The PVC and other namespaced chart
   resources were created. Helm status `deployed` is resource-creation success,
   not gateway readiness: the fixture pod and PVC remained Pending by design.
2. At 11:28 IST, actual `helm upgrade` with matching canonical organization and
   lifecycle-claim values succeeded, revision 2. PVC UID, spec and annotations
   matched the pre-upgrade snapshot.
3. Actual `helm upgrade` with a different canonical organization UUID failed
   during rendering at `templates/pvc.yaml:1:4` with:

   ```text
   organization and lifecycle-claim must exactly match persistence.provenance;
   refusing to relabel retained identity state
   ```

4. Full PVC JSON before and after refusal was byte-identical (`cmp` exit 0).
   Helm remained at revision 2; no failed revision 3 was created. The fixture
   pod had no `spec.nodeName` and no container statuses. Its PVC had no volume.
5. Existing A3, B2 and edge gateway Deployments remained 1/1 Ready afterward.
   No working gateway was stopped, relabelled, reinstalled or manually repaired.

Fresh and matching install/upgrade rendering, malformed/missing provenance,
lookup failures and tokenless reuse also have the local 36-case actual-Helm
lookup matrix. This AWS proof is specifically chart/PVC metadata protection;
it does not claim gateway enrollment, persistent-volume content verification,
runtime readiness, atomic admission or new HA qualification.

## Retained test resources

The isolated fixture is left intact pending separately approved cleanup:
namespace `tunnex-pvc-guard-20260906-gstqsc`, release `pvc-guard`, its Pending
Deployment/ReplicaSet/Pod, service/NodePort, service account, unbound PVC and
Helm revision metadata. No test PV/EBS volume or cluster RBAC was created.
Do not include existing working gateway namespaces or retained volumes in cleanup.
No credentials, kubeconfig, certificate bodies or private keys are committed.
