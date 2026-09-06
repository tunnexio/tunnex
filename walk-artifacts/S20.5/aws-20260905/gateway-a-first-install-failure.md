# S20.5 — first gateway A failure, retained state and IAM correction

2026-09-05. The first ordinary CLI install of `tunnex-s205-a` in
`tunnex-s205-aws-20260905a` failed; **Leg 2 did not pass**. Previously accepted
Legs 0–1 remain documented in [candidate provenance](candidate-provenance-leg0-leg1.md).
This failed attempt adds no acceptance credit and does not establish a clean
baseline for any later candidate. It used source
`d2c9cba653d400e2dab3d7b038796efeee1f028c` and the published private candidate,
not manually substituted gateway manifests or host repairs.

## Observed failure and independent storage success

Gateway pod `tunnex-s205-a-tunnex-gateway-6cbc5bc48b-mp9kg`, UID
`6995ce4a-1c2e-4055-aff6-531841a35abd`, scheduled on worker A
`i-0afe3c3ecd00d1411`, host IP `10.240.10.204`. It entered CrashLoopBackOff;
the startup probe to `http://10.240.10.204:9091/healthz` reported connection
refused. Gateway startup is a separate product defect under investigation;
this evidence does not attribute it to the load-balancer IAM failure.

The root operator reported the ordinary CLI's terminal failure at
`2026-09-05T13:55:31.821Z`: Helm atomic installation exceeded its deadline,
and bootstrap Secret `tunnex-s205-a-bootstrap` was retained for bounded retry.
No manual delete, restart, host change, CNI repair or Secret-value read was
used to recover this attempt.

CSI successfully provisioned the 1-GiB encrypted gp3 volume
`vol-091ad45df24c5186b` in `ap-south-1a`. Before rollback it was attached to
worker A with DeleteOnTermination=false. PVC/PV details retained below are
metadata only; the identity filesystem contents were not read.

## LBC failure and one-action correction

The Service's `FailedDeployModel` event at `2026-09-05T13:51:01Z` reports
HTTP 403 `AccessDenied` for `elasticloadbalancing:DescribeRules`, request ID
`15abba2a-c831-4635-8a9c-17f54ea36f6e`, on role
`tunnex-s205-aws-20260905a-LoadBalancerControllerRol-YUliy4hHDzXM`.
The live inline policy independently read back HasDescribeRules=false before
the update. Earlier CreateLoadBalancer account refusals were followed by
actual NLB creation and are not a continuing account-creation diagnosis.

Before rollback, NLB `tunnex-s205-a` existed with cross-zone=true, the exact
two task subnets and supplied frontend SG. Its listener was UDP 51820; its
target group was IP/UDP 51820 with HTTP 9091 `/readyz`, success 200. No
TargetGroupBinding or registered target existed. This was not a healthy NLB
or successful packet path.

Paper-first decision `4e8b8a0` preceded code
`19089dd4ee208370682d9840befd81d0a61f2251`. The only template change adds
DescribeRules to the existing Mumbai-only read statement. Byte comparison
and parsed-template equality after removing that action passed; all seven
resources, trust, tags, parameters and other permissions remained unchanged.
AWS validate-template passed with CAPABILITY_IAM.

The exact UPDATE change set was:
`arn:aws:cloudformation:ap-south-1:735391218823:changeSet/controllers-describe-rules-19089dd/eb8e50f7-f994-49e4-ab26-9634d0b8999f`.
Its preview contained exactly one non-replacing LoadBalancerControllerRole
Policies modification. The policy preview was truncated, so actual current
and proposed Original templates were fetched and compared; they differed
only by the single action. Actual parameter values and tags matched without
printing the administrative CIDR.

After independent root review and fresh identity verification, the root
operator executed that exact change set with rollback disabled. Stack
`tunnex-s205-aws-20260905a-controllers` reached UPDATE_COMPLETE at
`2026-09-05T14:00:16.056Z`, event
`1f1e3b90-a932-11f1-8b7c-061e136c730b`. Live role readback confirms
DescribeRules present, Resource `*`, and unchanged RequestedRegion
`ap-south-1`. No Rule mutation actions or broader IAM permissions were added.

## Post-rollback census

Readbacks through approximately 14:04 UTC establish:

| Object | Actual observed disposition |
|---|---|
| Gateway Helm release | Absent from all-namespace/all-status Helm list |
| Gateway Pod, Deployment, DaemonSet and Service | Absent from the task namespace |
| NLB `tunnex-s205-a/2533766a582e702d` | Exact-ARN read returns LoadBalancerNotFound |
| TG `k8s-tunnexs2-tunnexs2-47f399e6db/261d5444caf8e15d` | Exact-ARN read returns TargetGroupNotFound |
| PVC `tunnex-s205-a-tunnex-gateway-state` | Bound, UID `8a8a39dd-527b-487d-a93a-162610102b81`, 1 GiB |
| PV `pvc-8a8a39dd-527b-487d-a93a-162610102b81` | Bound, UID `4bee8ae4-c008-4c86-857d-3c1a8bb96ead`, Retain |
| Volume `vol-091ad45df24c5186b` | Available, encrypted, attachments empty; not deleted |
| Bootstrap Secret `tunnex-s205-a-bootstrap` | Retained immutable object, UID `2b913c8c-1e6a-452d-99fa-a4878e2c9c14`; no data read |
| Lifecycle ConfigMap `tunnex-s205-a-lifecycle` | Retained, UID `3b8cacd9-7642-414d-9786-a3eb27ab4599`; metadata only inspected |
| Host-posture Helm release | Deployed revision 1 in `tunnex-system`; candidate chart/version unchanged |
| Host-posture manager DaemonSet | 3 desired / 3 ready / 3 available; all three pods Running, zero restarts |
| LBC Helm release | Deployed revision 1, chart 1.14.1 / app v2.14.1 |

The Service recorded normal `DeletedLoadBalancer` at **13:55:27Z**, before
the IAM update, followed by a finalizer-add race against the already-absent
Service. Thus ordinary atomic/controller cleanup—not this read permission
change or a manual delete—removed the NLB/TG. The successful IAM readback
does not prove that a new gateway now reconciles: the failed Service was
already gone. Fresh ordinary creation, target health and packet proof remain.

## Supported recovery boundary; no recovery invoked

Token-blind metadata reports bootstrap generation 1, expiry
`2026-09-05T14:45:13.05407Z`, owned by the exact lifecycle ConfigMap UID above.
The anchor remains `installing` with operation
`3adc6a9b-6170-48e6-997a-1b9410bbdcb5`, epoch 1, deadline
`2026-09-05T13:56:18.069295Z`. These are observed metadata, not proof of the
control plane's current operation state or whether enrollment occurred.

The install operation binds the approved image/chart and other intent inputs;
`apps/cli/internal/cli/k8s_install_operation.go` rejects changed inputs while
that persisted binding remains. The still-unexpired Secret is therefore not
permission to rerun a different image over this state. After the startup fix,
begin with the ordinary read-only plan and its exact CP/Kubernetes checks.
The existing expired-Secret recovery path may CAS-retire/remint only after
expiry and proof of retry-safe lifecycle, workload and retained-claim state.
Alternatively, the supported typed `abort-install` path requires review of
its exact targets and retained-state effects. Neither was invoked here.

Do not manually edit/delete the Secret, anchor or PVC, inspect the token, purge
the retained volume, or silently weaken the install-intent binding. Host-posture
readiness does not prove post-rollback kernel restoration. No product cleanup
leg, new-candidate baseline, all-gates pass, PR or release is claimed.
