# Organization admission and repeatable Linux deployment

The user authorized source fixes before PR preparation on2026-10-05. This story
removes the fixed human creator/device restriction and prepares repeatable,
cloud-independent installation on supported Linux. No live activation, new
credentials, provisioning, sandbox creation, publication or remote CI is allowed.

## Locked decisions

1. Add explicit persistent `organization` admission. The deployment still pins
   one nonzero organization, runtime and terminal gateways, qualified profiles,
   image digests, resource ceilings, expiry and trust references. Creator/device
   config values must be absent in this mode; mixed or wildcard configs fail.
   Missing admission retains legacy exact creator/device behavior and serialized
   binding bytes. Trial mode remains pinned.
2. Organization-mode Create requires `terminal_device_id`, an optional pointer
   field on the wire to preserve legacy intent hashes when omitted. Creator comes
   from the existing authenticated/RBAC actor, including existing bounded machine
   delegation. Verify an active, healthy human device in that org owned by that
   creator, on the configured terminal gateway, within the existing org lock.
   Include explicitly supplied device in the idempotency hash. Persist the exact
   creator/device once; runtime jobs derive them from the stored sandbox.
3. Keep one shared retained-workload slot. This is capacity, not a selected user.
   No multiplexing, autoscaling or increased host budget is included. Org/user
   quotas are the lower of configured org settings and supported deployment
   ceilings. Concurrent members serialize on the org lock; deleted but unretired
   records retain capacity. Setup must report these actual bounds.
4. Start/resume/Ready/runtime authentication revalidate current owner/device and
   grant eligibility. Bounded reconciliation requests deletion when authority is
   withdrawn, including membership/device loss in organization admission. Cleanup
   uses immutable stored identity even after revocation; it never requires the
   lost authority to permit deletion. Existing generation, delegation, policy ACK,
   confirmed withdrawal and retirement fences stay mandatory. An offline runner
   receives withdrawal after reconnection; its original absolute TTL remains the
   local hard bound. No instant closure of prior SSH from a DB change is claimed.
5. Runtime authorization permits any nonzero stored creator/device only under
   explicit organization admission. Worker sameWorkload, leases and durable state
   keep that exact identity. Drain and confirm retirement before switching an
   active legacy deployment's authority mode. No rebinding or TTL extension.
6. DevReservation remains an exact historical compatibility exception in legacy
   qualification mode. Organization admission rejects it. It is not generalized
   into an arbitrary reserved-workload or quota bypass.
7. State/run roots and actor-control cgroup placement come from trusted operator
   configuration, with clean absolute/nonoverlapping paths and exact native
   placement/owner/resource validation. They never come from sandbox requests.
   Legacy defaults remain available for existing configs. Preserve cgroup expiry,
   kill/freeze and descendant ownership fences.
8. Provide stdlib-only offline Linux plan/check/install tooling. Operator-selected
   UID/subUIDs, public org/gateway/template/image/trust pins, verified local binary
   bundle/image archive and bounded storage replace research-host arrangements.
   Refuse collisions, unknown pins, unsupported capabilities and unbounded values.
   Install leaves services disabled/stopped; it downloads nothing, generates no
   credentials and performs no cloud action. Existing host systemd/cgroup v2,
   rootless Podman/runc/native overlay and local Docker gateway inspection remain
   explicit supported prerequisites, rather than per-launch dependency installs.
9. Linux AMD64 has the recorded native qualification; ARM64 compilation does not
   establish activation support. CI builds/checks public artifacts and synthetic
   bounded fixtures, with no live AWS smoke. Workload image recipes must retain
   honest qualification labels; the failed Alpine policy path is not declared
   supported. General Windows/macOS runner hosting is not claimed.
10. First-Ready-relative usable TTL is excluded and remains unimplemented. Existing
    absolute Create-relative expiry and all completed UI/skills/lifecycle work stay.

## Validation

Test two authorized members sequentially and concurrent quota races; independent
owner idempotency; changed/foreign/reassigned/agent/blocked devices; cross-org and
cross-owner refusal; member/grant/device revocation and exact cleanup; restart
identity, legacy replay/serialization and stale-generation refusal. Run both API
editions, generation and combined migrations. Installer tests use synthetic host
metadata and temporary files; validate ownership, collision refusal, checksums,
capabilities, bounded unit rendering, disabled install and no dependency downloads.
Existing native proofs remain evidence of their actual scope, not a substitute
for a newly activated production deployment.
