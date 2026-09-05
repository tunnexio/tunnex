# User-approved NodePort transition

User disposition: skip NLB path. Decision `f4051a1`; NodePort prerequisite
source `b0deaef`. NLB qualification stays skipped, not passed.

## Native retirement of failed fixtures

- B install terminated exit 1 at 15:39:09.671Z after native abort request.
  Native B abort ran 15:38:54.151Z to 15:39:36.627Z, exit 0,
  exact claim `ca93d1b5-8444-4044-8412-7d512f07a1ce`.
- A2 native abort ran 15:39:44.560Z to 15:40:04.043Z, exit 0,
  exact claim `f35ad94d-0457-461e-87fe-86058fecd9ea`.
- Readback: gateway Pods/Services, bootstrap Secrets and lifecycle anchors
  absent; only default namespace root-CA ConfigMap remains. Original A, A2 and
  B PVCs remain Bound. No Secret data was read; no manual host/PVC repair.

## Restricted ingress and fresh plans

Fresh worker readback verified the exact task VPC and running instances:
A3 worker `i-0f6bb7eca4b726637`, public `13.234.118.111`; B2 worker
`i-03c1fb3619712c8d3`, public `13.206.207.103`. Both use task worker SG
`sg-0a4645cf6d8de2c33`. Client external IPv4 rechecked `122.183.45.166`.
Neither selected NodePort was already allocated in the cluster.

CloudFormation changeset `controllers-nodeport-20260905`, identifier
`c28b210f-2264-4124-a972-118c26fb2d5f`, previewed exactly two ingress additions:
UDP 31081 and 31082 from client /32 to task worker SG. No replacement, other
network changes, IAM expansion, or machine creation. Stack UPDATE_COMPLETE
verified. Existing NLB resources/rules were not removed as incidental cleanup.

A3 native plan ran 15:41:07.855Z to 15:41:17.869Z, exit 0. A3 install is
underway using the unchanged six-image/four-chart source `61ecc5f`; B2 has a
separate read-only plan. These are progress observations, not completed legs.

## Native install completion and host readback

A3 install completed 15:41:50.275Z to 15:42:46.353Z, exit 0.
B2 plan completed 15:41:59.710Z, exit 0; install completed
15:43:11.974Z to 15:44:11.950Z, exit 0. Both observed 1/1 Ready,
zero restarts, on their separate selected workers.

CP at 15:44:34Z returned both active with exact candidate agent_version:

| Release | Node ID | Endpoint |
|---|---|---|
| A3 | 01a0723c-6553-731c-be92-760743713716 | 13.234.118.111:31081 |
| B2 | 01a0723d-a324-7c52-9c99-2468e51f2e6c | 13.206.207.103:31082 |

Read-only SSM command `ebbc5b67-2383-4f75-9b60-8d98a0f04ea2` succeeded
on both workers at 15:44:09Z (exit 0). Both returned schema-3 active journals,
epoch 2, committed WireGuard phase, matching final/staging recorded ifindices
(A3 8, B2 9), final `wg0` WireGuard links with exact
`tunnex-host-posture/v1` alias, and no staging link among live WireGuard links.
Both journals contain the AWS-SNAT-CHAIN-0 receipt. Active heartbeats bind the
exact gateway Pod owner; ip_forward=1, wg0 rp_filter=0; local /readyz returned
`{"status":"ready"}`. These final snapshots do not alone prove every earlier
durable phase transition; that detailed chronology remains to be collected.

No client VPN traffic, distinct public-key proof, private-Service grant,
GitOps or HA failover is claimed yet. Successful one-command installations do
not complete the whole walk. Existing Scale license remained valid throughout.

Post-install Secret-name readback showed only the two Helm release records,
no bootstrap Secrets; no lifecycle ConfigMaps remain. A3 PVC UID
`355a26b0-022d-4710-b10c-85fae3375418` and B2 PVC UID
`8eb91d90-453a-4412-b18c-8e28d587caae` are distinct, Bound, retained 1Gi.
Installed local desktop version still reads 0.1.1; the exact-candidate package
is built but its normal privileged installation remains required for that
candidate's managed-client proof.
