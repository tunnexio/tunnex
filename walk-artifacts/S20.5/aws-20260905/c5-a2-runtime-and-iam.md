# C5 A2 runtime admission and AWS prerequisite failure

Candidate: `61ecc5fec4e5a971faaf9b1c65ccdc7b3b4cd8c1`.
Native install ran 2026-09-05T15:19:37.832Z to 15:30:24.383Z, exit 1.

Observed gateway logs show enrollment at 15:20:29, waiting for two advancing
exact-owner CNI heartbeats, then `k8s_cni_runtime_admitted` at 15:20:31 and
ordinary reconciliation. At the observation the gateway had zero restarts and
the host-posture DaemonSet was 3/3 Ready. This proves the formerly failing
startup transition on this attempt, not full lifecycle or VPN acceptance.

The controller returned AWS 403 CreateLoadBalancer for the exact NLB
`tunnex-s205-a2`: the fixture policy allowed A and B names, but not A2.
The gateway Service remained endpoint-pending. Helm's native atomic install
timed out and removed the gateway workloads and Service. The native CLI
reported retained bootstrap recovery metadata; readback showed the A2 lifecycle
anchor and Bound retained PVC, no gateway Pod or Service. No manual Secret,
PVC, CNI, Service patch, or remedial rollout restart was performed.

The correction adds A2 only in five existing resource ARN lists, leaving
actions and conditions unchanged; decision `c58692c`, source `a11f49c`.
Fresh STS readback verified account `735391218823`, principal `aws-cli`.
CloudFormation changeset `controllers-a2-name-20260905`, identifier
`407cb2d0-a69b-467b-89ad-53c850ade8c3`, showed exactly one modification:
LoadBalancerControllerRole Policies, replacement false, recreation never.
Execution completed with stack status UPDATE_COMPLETE. No other stack resource
was changed. The failure had already occurred before this update; it is not
retroactively a passing install. A fresh native recovery plan is required.

Leg 2 remains incomplete. No PR, merge, release, or exact-final CI success is
claimed by these observations.

## Bounded retry after IAM correction

Fresh plan passed at 15:32:34.011Z, describing existing bootstrap metadata and
retained PVC reuse. Actual install retry ran 15:33:24.167Z to 15:33:43.836Z,
exit 1: `control-plane lifecycle claim is "consumed", not retry-safe`.
No gateway Pod or Service existed after this refusal. No guard was bypassed;
recovery metadata and retained storage remain for native lifecycle disposition.
This also shows that a successful plan is not proof that the subsequent live
control-plane check will authorize an install. Separate planned B preparation
continues; B success cannot retroactively pass A2 or prove two-gateway HA.
