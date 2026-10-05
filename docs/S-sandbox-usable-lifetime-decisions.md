# Sandbox usable lifetime decisions

Status: proposed source-only contract correction, 2026-10-05. No migration, runtime change, deployment, lease extension, or new trial is authorized by this paper. Existing live and historical leases retain their original deadlines.

The requested behavior is that the user's selected usable lifetime starts at the **first canonical Ready**, after the existing policy, network and pinned SSH gates pass. Provisioning consumes a separately bounded resource period. Stop/Resume and later Ready transitions preserve the first usable absolute expiry; stopped time still counts. This changes lifetime accounting and does not fix slow startup. The latest single native samples took 290.091 seconds from Create to canonical Ready and 146.094 seconds from Resume to Ready; these are not benchmarks.

## Current contract conflicts

`Store.Create` currently sets `expires_at = now() + ttl_seconds`. The [0167 identity trigger](../apps/api/db/migrations/0181_sandboxes.up.sql) forbids changing either `created_at` or `expires_at`. [Readiness](../apps/api/internal/sandboxes/readiness.go) only changes observed state and audits Ready; it establishes no persistent first-Ready timestamp. Start, runtime authentication, desired-state changes and cleanup all use the same creation-based expiry.

The [runner lease](../apps/api/internal/sandboxrunner/lease.go), [actor authorization restoration](../apps/api/internal/sandboxes/runtime_actor.go) and [independent cgroup guard](../apps/api/internal/sandboxruntime/cgroup_lease_guard.go) pin the same original creation/expiry interval. They reject deadline changes and currently admit at most 900 seconds from creation to expiry. Forward generations preserve that timer; a fenced scope never thaws. Changing only the database would fail these checks and leave the offline execution fence on the old deadline. Adding provisioning time to the current 900-second bound would also broaden resource authority and needs an explicit new contract.

## Proposed durable lifecycle

Persist immutable creation intent: `created_at`, requested usable TTL, `provision_deadline`, and a total resource deadline ceiling admitted at Create. Also persist initially absent `first_ready_at` and `usable_expires_at`.

The first generation-fenced canonical Ready transition sets `first_ready_at` once, using the authoritative database clock, and derives `usable_expires_at = first_ready_at + requested_ttl` in that same transaction. A database invariant must prevent subsequent changes, partial pairs, caller-supplied timestamps, and values beyond the admitted total ceiling. Do not repurpose `created_at`. Migration behavior for existing records must preserve their current creation-based expiry; a contract version distinguishes them from newly admitted records.

Before first Ready, the effective execution deadline is `provision_deadline`; after first Ready, it is the immutable usable expiry. Authority revocation, delegation expiry and current admission can close access earlier. If the requested full usable TTL cannot fit within the user's admitted authority envelope at first Ready, refuse readiness and clean up rather than silently extend that authority. Quotas include creating/starting workloads and retained resources until confirmed cleanup.

Never-Ready workloads cannot wait indefinitely. At the provisioning deadline, fence execution and request deletion through existing reconciliation. User cancellation, organization opt-out and authority withdrawal use the same bounded cleanup. Ready racing cancellation, revocation or provision expiry must lose when its current generation/admission/deadline checks fail. Retries and duplicate Create delivery reuse the existing identity and immutable deadlines; no retry resets provisioning time.

## Actor lease and offline ordering

Define a versioned lease with explicit provisioning and usable phases, immutable creation/provision/total bounds, an optional committed first-Ready pair, and a monotonic transition identity separate from lifecycle generation. Permit exactly one authenticated provisioning-to-usable promotion for that sandbox and its bound runtime/spec. Ordinary generation advancement, transport restart and Resume cannot alter either deadline. Reject malformed bounds, stale or conflicting promotions and any promotion after the provision fence wins. Keep the independent timer outside provider/effect locks and retain frozen tombstones; never thaw an expired scope.

Use a durable canonical promotion record/outbox and an idempotent actor receipt. A runtime-provided claim of readiness cannot authorize the transition. The actor must persist the accepted committed values before acknowledging promotion, arm the exact absolute usable deadline, and recover those values after crash. Recovery never calculates `now + TTL`. Lost responses retry the same transition, not a later timestamp. An offline actor without an accepted promotion retains its provisioning deadline; after accepted promotion it enforces usable expiry without the transport. Execution fencing remains distinct from confirmed provider/network/assets cleanup and address release.

The DB Ready commit and actor persistence are not one atomic operation. **Ready publication semantics remain unresolved:** specify precisely the first canonical Ready linearization point, actor durable acknowledgement, and when UI/API may expose a usable connection. A DB commit followed by lost delivery can otherwise advertise Ready while the actor still has the provisioning fence; installing usable authority before DB commitment can let a never-Ready workload exceed its provisioning bound. The protocol must account for both windows with durable recovery and a fail-closed outcome, without claiming distributed atomicity or silently charging delivery delay to the user. This decision must be settled before implementation.

## Open bounds and required validation

The maximum provisioning duration (`Pmax`), total resource cap, and their template/org admission rules are unresolved. No new approved values are inferred here. Provisioning must have a finite maximum and total authority must be explicit; the new contract cannot silently relax the current 900-second creation-to-expiry guard. Account for any cleanup retention separately from the hard execution deadline.

Required boundary tests cover duplicate Ready/promotion delivery; cancellation or revocation racing Ready; provision expiry racing a blocked provider call; never-Ready timeout; crash and disconnect before/after each DB/actor durable write; recovery from a newer lease than its execution pin; stale generations; existing-record compatibility; Resume without extension; and offline usable expiry. Verify exact cleanup separately. Acceptance also requires measured Create-to-ready and Resume-to-ready latency; correct lifetime accounting cannot substitute for meeting the lightweight startup requirement.
