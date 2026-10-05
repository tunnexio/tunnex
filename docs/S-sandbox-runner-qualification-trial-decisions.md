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
- Locked proof boundary: canonical policy acknowledgements, lifecycle and
  confirmed retirement combine with the authenticated machine offline witness
  and mandatory administrator review. Existing private SSH readiness is probed
  by the runner and is explicitly recorded as runner-origin evidence. This is
  not independent terminal-side SSH proof. Source fixtures do not establish
  native qualification.
- Deferred: additional profiles, ARM64 activation, capacity expansion, automatic
  approvals and performance claims beyond measured receipts.

The public begin request is `{terminal_device_id, ssh_public_keys,
idempotency_key}`. The trial response includes IDs, canonical desired/observed
states and generation, phase observations, original created/expiry times,
blocked reasons and a public customer qualification command when its actual
producer is available. Connection metadata is provided only while the existing
canonical connection gates pass.

Host enrollment is the administrator-managed host certificate, probe identity,
trusted source/profile pins and qualification. Each ordinary workload retains
its creating user's org membership, own terminal and permitted policy scope.
The enrolled first target accepts one Ubuntu26.04 AMD64 image profile, one
retained workload and original900-second lifetimes. Static legacy bindings keep
their existing profiles. Additional images require their own qualified trial
coverage; they cannot inherit this host's first-image proof.

The source pump runs in the existing bounded orchestrator batch, never a second
service. Successful Ready and Stopped transactions append immutable public
receipts. Expiry and withdrawal request deletion; completion requires actual
Deleted plus worker retirement and the authenticated local offline witness.
The observer's bounded collection window is evidence collection time, not a TTL
extension or an instant physical-stop guarantee. Actor receipt timestamps are
sampled sweep times persisted only after confirmed provider stop.

Ordinary Create has a pre-transaction availability check and a transaction
admission hook that binds the current qualified enrollment to the immutable
workload. This prevents a revoke between the initial check and commit from
leaving an unmapped retained slot. Current per-command/generation authorization
remains required. Trial admission has its separate grant/mapping in the same
creation transaction and bypasses only ordinary runner readiness/catalog flags.

Source validation includes disposable PostgreSQL grant/admission/immutability
fixtures, composed source start-stop-resume and confirmed cancellation retirement
with synthetic runtime/network/SSH adapters, strict mTLS private trial routes,
and real Python completed-report producer bytes consumed by the exact-hash
administrator review flow. Historical synthetic canonical receipts exercise the
full expiry witness/proof contract without waiting900seconds. These fixtures do
not establish native host qualification, independent terminal SSH observation,
physical900-second stop timing, deployment compatibility or measured latency.
