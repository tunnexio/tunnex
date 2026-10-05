# Prompt applied-policy acknowledgement

## Source and authorization

`story/sandbox-readiness-diagnostic-live`, using an isolated source checkout.


Baseline is `6adb6994dcde54bb1d159a7d0d08d22ec54ea7c0`; the deployed API remains
the previously recorded diagnostic build. The parent authorized tracing the
dispatch/apply/report/reconciliation path and a narrow, evidence-backed prompt
report/wake fix with focused success, failure, retry, and concurrency tests.
No deployment, live trial, access expansion, credential change, or TTL change.

## Findings

1. Policy changes already reach the node through the versioned desired-state
   watch. `OnPolicy` applies egress policy inline on the existing serialized
   command lane.
2. The node starts its report loop before initial desired-state application.
   Applied policy changes do not wake it; after the first successful report it
   otherwise waits for endpoint/AI notification or the default 30-second timer.
3. After initial success, a failed report is currently discarded until another
   wake or heartbeat. Initial startup failures already use bounded retry.
4. The API authenticates `/agent/report` by client certificate, persists only
   the active certificate-selected node, and stamps policy report time on the
   server. It returns success without waking sandbox reconciliation, whose API
   loop currently ticks every second.
5. `AppliedStatus` describes actual last successful application. An apply
   failure preserves its last-good hash and advertises the failure. Sandbox
   readiness separately requires exact canonical hash, freshness, health,
   organization, device, and binding evidence.

These source findings establish a timer contribution worth removing. They do
not establish the running gateway binary/configuration during the retired
trial or explain every earlier startup delay. Existing HTTP timeout, desired
watch recovery, peer telemetry cadence, and actual network/apply time remain.

## Decisions

- **Locked: report after an observed applied-status change.** Add a buffered,
  nonblocking notification after inline policy reconciliation and periodic
  egress recovery. Compare actual applied outcome/capability state; repeated
  no-op application must not create a report/reconciliation feedback loop.
  Desired policy or a wake alone never supplies an acknowledgement hash.
- **Locked: keep one reporting goroutine.** It snapshots actual state at send
  time. An in-flight older report completes before a queued newer report; no
  HTTP request runs on the command lane and no parallel report can overwrite a
  newer hash by finishing late.
- **Locked: bounded retry applies after every failed report.** Preserve the
  existing one-second minimum and 30-second maximum backoff. A change wake can
  interrupt retry; successful sends reset it. Preserve the heartbeat and
  endpoint-generation acceptance checks.
- **Locked: successful persistence wakes the existing sandbox worker.** Add an
  optional startup-wired callback after `ReportWGInfo` succeeds. Invalid,
  unauthorized, revoked, or rejected reports do not wake it. The worker still
  reads canonical state through its existing scoped gates.
- **Rejected: shorten heartbeat globally or report concurrently.** Global
  polling adds idle traffic; concurrent sends permit report ordering races.
- **Deferred: peer telemetry scheduling, HTTP timeout changes, TTL changes,
  wider orchestration changes.** They require independent evidence and scope.

## Stories and acceptance

1. **Node acknowledgement scheduling** (depends on this paper): a changed
   successful apply queues a prompt actual-hash report; a failed apply reports
   old hash plus error; periodic recovery queues its new outcome. Unchanged
   reconciliation queues nothing. After first success, a report failure retries
   without waiting for the normal heartbeat. Burst notifications coalesce and
   never overlap HTTP reports. Cancellation terminates retry.
2. **API reconciliation notification** (independent after this paper): the
   certificate-selected active node's persisted hash and server report time
   exist before the callback; body identity cannot redirect persistence;
   decode/authentication/service failures never notify. Nil callback preserves
   the older behavior. Wire fields/schema are unchanged.
3. **Focused qualification** (depends on both): node scheduler/change tests,
   real local PostgreSQL report-ingress tests in both API editions, and the
   existing exact-hash/freshness/org/health readiness rejection cases pass.
   Record race results and applicable compile checks. No broader audit or live
   operations are part of this task.

Local tests are substitutes for wire qualification. A future separately
authorized rollout/trial must measure policy apply-to-report-to-Ready timing
before claiming an end-to-end improvement. No instant-start guarantee.
