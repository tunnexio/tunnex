# Customer runner qualification trial decisions

This paper records the explicitly authorized source addition after runtime
integration ea81e3189427f0c52a409b156054d9e46e20a2d2. No native trial is run by
implementing or testing this workflow.

- Locked: qualification creates one canonical, human-owned sandbox through the
  existing admission, quota, lifecycle, policy and cleanup machinery. The admin
  needs both runner management and sandbox creation permissions and must select
  their own current human terminal and public SSH key. Machine delegation cannot
  begin a trial.
- Locked: the grant binds one enrollment, current certificate SPKI, public probe,
  source/binding hash, admin, terminal, trusted template and sandbox. It uses an
  empty outbound scope, no skills, 128 MiB, one CPU, 64 PIDs and the original
  lifetime of at most 900 seconds. The same retained slot includes the trial;
  cleanup must be confirmed before replacement or another workload.
- Locked: a disabled organization/catalog can admit only this distinct trial.
  The database trigger and execution/policy predicates recognize its exact
  durable grant. No ordinary organization flag, role or broad policy is enabled.
  Enforcing policy and current human/device authority remain mandatory.
- Locked: unqualified transport credentials may execute only that trial's
  already bounded lifecycle. The enrollment service uses a trial validator for
  every relevant command. Nil or invalid trial authority remains closed.
- Locked: the control plane records actual canonical Ready, stop, stopped,
  resume Ready, original expiry, withdrawal, deleted and retired observations.
  It does not replace physical observations with desired state updates.
- Locked: the customer explicitly invokes the machine observer. It validates
  its own durable actor/runtime identity and pauses only its own transport,
  leaving the actor/helper running through original expiry. It observes exact
  provider/cgroup absence and restarts transport. No TTL extension or unrelated
  service operation is permitted.
- Locked: public witness upload uses current, active mTLS authority and exact
  trial/source/binding identity. Rejected or incomplete witnesses cannot turn
  checklist booleans into qualification. Reports and native evidence require
  explicit human review before ordinary runner readiness.
- Pending independent observation: existing private SSH readiness is probed by
  the runner. A runner report alone is not an independent terminal-side SSH
  proof. The final qualification verifier must record the chosen trusted proof
  boundary; source fixtures are substitutes for native evidence.
- Deferred: additional profiles, ARM64 activation, capacity expansion, automatic
  approvals and performance claims beyond measured receipts.

The public begin request is `{terminal_device_id, ssh_public_keys,
idempotency_key}`. The trial response includes IDs, canonical desired/observed
states and generation, phase observations, original created/expiry times,
blocked reasons and a public customer qualification command when its actual
producer is available. Connection metadata is provided only while the existing
canonical connection gates pass.
