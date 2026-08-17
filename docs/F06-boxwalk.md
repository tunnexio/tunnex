# F06 — Agent ownership and delegated RBAC box-walk

Status: **SATISFIES** on exact DEV content `8c3fed8`. Redacted evidence:
`walk-artifacts/F06/20260816T0410Z/f06-aws-dev-live-redacted.md`. This was one
combined acceptance walk; F01–F05 were prerequisites and were not repeated.

## Safe scope

- Use only the authorized AWS DEV control plane and clearly named disposable
  F06 agent, group, members, and policy rule.
- Record the exact commit, API/web image digests, schema version, backup proof,
  and pre-walk agent tunnel/runtime revisions before mutation.
- Never record cookies, bootstrap/runtime credentials, token hashes, WireGuard
  private keys, or configuration bodies. Evidence contains IDs, statuses,
  counts, revisions, response codes, and digests only.

## Checklist

- [x] Deploy the exact committed API/web build; migrate cleanly to schema 95;
      retain verified rollback images and database backup.
- [x] Owner/admin assigns a current member as accountable owner and one
      current-org group as managing team through the released Agents page.
      Refetch persists both and audit records the old/new assignment.
- [x] Assignment leaves device ID, address, gateway, grants, runtime PID,
      desired/applied revisions, credential/key revisions, and real handshake
      unchanged.
- [x] Accountable member can view privileged profile/runtime/rotation facts and
      manage lifecycle for only that owned agent. Assignment, enrollment,
      rotation, and access-grant actions are absent.
- [x] Managing-group member can view/manage only the delegated agent. Revoke,
      assignment, enrollment, rotation, and grant actions are absent.
- [x] Unrelated member receives the uniform forbidden response for known and
      unknown agent IDs. Owner/team/profile/runtime/rotation facts and actions
      are absent from the released DOM.
- [x] Authorized policy operator creates, refetches, and edits one agent-source
      grant in the released Access page. A principal without
      `agent:grant_access` cannot call or render agent-source authoring; ordinary
      non-agent policy work remains available according to its existing role.
- [x] Switching organizations synchronously removes the prior org's agent,
      rule, assignment candidates, permission summary, and expanded details
      before the next org finishes loading.
- [x] Removing the delegated member withdraws scoped authority immediately.
      Deleting the disposable managing group clears delegation, preserves the
      accountable owner and running tunnel, and states both delegation and
      policy-rule impact before confirmation.
- [x] Suspend/resume preserves ownership and delegation while exercising the
      established F04/F05 offboard/recovery path. Revoke states tunnel/runtime
      stop, pending-rotation cancellation, and saved-grant non-match; a remove
      failure cannot hide a successful revoke.
- [x] Disposable PostgreSQL proves empty 95→94 down, 94→95 up-again, and
      non-empty rollback refusal with assignment/device rows unchanged.
- [x] Cleanup removes only F06 disposable identities, group membership, group,
      policy rule, agent, and host files; unrelated gateways, users, policies,
      peers, and AWS resources are unchanged.

## Completion ledger

Every checkbox is backed by the redacted evidence above from the exact deployed
build. Required local gates were green before deployment; live API/UI, wire,
PostgreSQL, restore, and cleanup evidence all refer to the same content tip.
