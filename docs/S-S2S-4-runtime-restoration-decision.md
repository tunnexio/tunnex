# S2S-4 runtime restoration decision

Status: user approved verified-reset cleanup and fresh CP authorization on 25 September 2026. Cleanup-only legacy recovery is being implemented and qualified; automatic restoration below remains a separate, unimplemented extension.

## Problem and observed boundaries

Recreating the isolated AWS lab gateway container removes its kernel XFRM interfaces but preserves the node journal. An applied delivery retains the old interface indices. Automatic restoration currently refuses; supported disable, acknowledged cleanup and a new delivery restore service.

Four guards explain this behavior:

- `RuntimeController.Apply` compares the saved delivery with an entry built for the current network namespace. A namespace change fails immutable-entry comparison.
- `applyRecovery` creates kernel objects only for Reserved or Applying entries, not Applied entries.
- `KernelApplier.Apply` rejects a missing or changed interface when nonzero prior ownership was recorded.
- `validJournalSuccessor` makes the allocation namespace immutable and prohibits Applied → Applying.

These protections must remain for ordinary apply and cleanup. A process restart with intact kernel state differs from a kernel reset. Existing process-restart proof does not establish host-reboot recovery. A namespace inode may be reused; its equality alone does not prove continuity.

## Proposed contract

Add an explicit, durable **restoration obligation**, separate from permit authority and ordinary delivery application. Keep the CP delivery/configuration/policy identities and the prior ownership obligation; record a monotonically increasing local restoration epoch and new kernel generation. Do not overwrite old ownership or reset the journal in place.

Restoration requires all of the following before object creation:

1. Exclusive node journal/controller ownership and current platform qualification.
2. Independently verified permanent prefix refusal in the current namespace. No persisted permit or old lease is reused.
3. Fresh CP material confirming the same enabled delivery, configuration, policy and gateway binding. Acquire current authorization before restoration mutations and revalidate it before permitting traffic.
4. Bounded, complete observations proving both prior tunnels absent: no matching names, ownership aliases, XFRM interface IDs, reqids, daemon children, states, policies, inside addresses or owned routes. Bracket reads by namespace/boot observations. Missing interfaces alone are insufficient.
5. A durably saved restoration reservation before creating any object. Save new observed ownership before it can be used for later mutation or cleanup.

Build both tunnel interfaces and required addresses/routes under refusal. Re-stage only the freshly supplied tunnel configuration and secrets. Require independent daemon/kernel agreement, current policy grants, fresh bounded lease and exact guard readback before permitting traffic. Restoration is not permission to alter cryptographic suites, adopt unknown objects or grant broader access.

The schema must distinguish CP delivery generation from local kernel restoration generation. Any allocation/alias/ownership binding affected by that separation must be specified and tested together; merely changing the existing generation field would break existing ownership invariants.

## Collisions, surviving objects and route duty

- Foreign, unlabeled, ambiguous or conflicting objects cause refusal without deletion or adoption.
- A partial survivor does not qualify as complete reset. Initially refuse automatic restoration and retain the exact cleanup obligation; use supported explicit cleanup and new delivery. Partial reconstruction can be a separate reviewed extension.
- Absence in a new namespace does not prove absence in an old namespace that might still exist. Namespace migration requires evidence that the previous runtime is gone and cannot forward, or explicit cleanup of that runtime. Otherwise remain refused.
- Preserve completed selected-slot duty, including slot 2; do not silently fail back to slot 1.
- Preserve an unfinished route transition's exact target and sequence. Resume only with fresh target health and authority; do not infer rollback from which tunnel happens to be healthy.
- If authorization is revoked, expires or the CP is unavailable, keep refusal and restoration/cleanup obligations. Do not make continued connectivity depend on saved permission.

## Crash behavior and required regression matrix

Every ambiguous filesystem or kernel mutation retains refusal. On restart, inspect the saved restoration phase and independently observed objects. Only objects attributable to that exact reserved generation may be reconciled. A crash before ownership stamping must not cause adoption by name alone.

| Case | Required result |
| --- | --- |
| Process restart, intact kernel | Existing strict ownership path; fresh authority before permits |
| New namespace, complete prior-runtime termination proof and empty owned inventory | Restore under a new local generation; verify traffic afterward |
| Reused namespace identity with missing links | Detect absence independently; never assume continuity from inode equality |
| Same names, changed indices/aliases or foreign XFRM IDs/reqids | Refuse without deleting/adopting foreign state |
| One surviving link, route, address, daemon child, SA or policy | Refuse automatic reset restoration; retain cleanup duty |
| Old namespace might still forward | Refuse migration until old-runtime termination/cleanup is proven |
| CP unavailable, disabled delivery, stale material, denied/expired lease | No permits; no restoration based solely on journal state |
| Crash before reservation / after reservation / after first link creation / before ownership save | Resume exact known duty or refuse ambiguity; no name-only adoption |
| Crash after object readback / before permit / after permit installation | Fresh proof and bounded authority; no stale lease resurrection |
| Saved slot 2 or pending slot change | Preserve selected duty or exact pending target; no implicit failback |
| Cleanup during incomplete restoration | Cover old and new generation obligations; acknowledge only proven absence |
| TCP/UDP during reset and recovery | No plaintext escape; independently verified encrypted payload resumes only after authorization |

Run unit fault injection first, then a dedicated Linux network-namespace reset test, then a real dedicated gateway-host reboot. Keep those evidence labels distinct.

## Host test boundary

The user's Mac runs shared Colima workloads, including the local CP and unrelated containers. Do not reboot Colima or the Mac as an isolated gateway-host test. Container recreation can prove container/kernel-namespace reset behavior only. A real host-reboot receipt requires a dedicated Linux gateway host and explicit approval to reboot that host, preserving the management machine and other workloads.

## Decision requested

Approve or revise the proposed restoration obligation, local generation separation, complete-absence requirement, prior-runtime termination proof and initial refusal of partial survivors before implementation. Until disposition and qualification, retain the existing supported disable/cleanup/new-delivery recovery path and leave automatic host-reboot restoration unqualified.


## Approved first stage: legacy cleanup only

A legacy journal has no historical boot identifier. Never manufacture one or infer termination from an absent namespace inode. A privileged host supervisor/operator that independently observed the old VM stop may supply a private root-owned receipt, explicitly attesting that event. This is operator-attested recovery, not autonomous historical-boot detection.

The receipt binds the node owner, exact CP cleanup identity/revision, digest of every covered immutable journal entry, current kernel boot ID and namespace, and digest of external lifecycle evidence. It is accepted only by Cleanup. The controller saves an immutable reset audit record in journal format v3, retains original Allocation/Observed and recovery duty, proves complete current absence without removing name-matching objects, drains relevant current conntrack under permanent prefix refusal, repeats absence/boot checks, then acknowledges cleanup. Apply never consumes this receipt; re-enabling requires a fresh CP delivery and permit lease.

Receipt file stays beside the journal as an audit artifact. Future cleanup retries must match the saved receipt digest. Missing, malformed, broad, foreign, unsafe-permission or symlink receipts refuse. Old readers reject journal v3 rather than silently ignoring the new duty; downgrade is therefore not supported after a reset receipt is reserved. Preserve the complete journal and use the new reader for rollback/recovery. Never restore a pre-cleanup journal snapshot to fabricate current ownership.

This first stage does not automatically reconstruct an enabled delivery or implement the local restoration epoch described above. Native namespace cleanup tests and actual lab recovery must be reported separately from dedicated host-reboot qualification.
