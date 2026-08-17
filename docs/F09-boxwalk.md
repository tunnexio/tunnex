# F09 — Agent groups and reusable policy templates box-walk

Status: **SATISFIES**.

The combined walk used exact committed F09 API/web content on AWS DEV, the
existing healthy DEV gateway, and two uniquely named disposable managed-agent
identities. Cookies, bootstrap credentials, private keys, raw configurations
and token hashes were never copied into evidence.

## Acceptance

- [x] Exact source labels, schema 97, healthy services and a verified rollback
      bundle were recorded before story mutations.
- [x] One two-agent group and immutable template v1 produced a pure preview for
      both agents; assignment/audit/rule counts were byte-equivalent before and
      after preview.
- [x] Apply materialized one ordinary assignment-owned rule; replay with the
      same idempotency key was a no-op.
- [x] Removing and restoring a member changed compiler expansion without rule-ID
      churn.
- [x] A stale preview refused with 409 before mutation.
- [x] Template v2 replacement created and removed exactly one generated rule,
      retained both immutable versions, and preserved one active assignment.
- [x] Referenced destination and assigned-group destructive operations refused
      with server-owned impact facts.
- [x] Removing the assignment withdrew the generated binding; group and
      template archive preserved immutable history.
- [x] Unrelated-member live API calls returned uniform 403 and contained no
      group/template facts. A fresh unrelated-member Chrome session rendered
      only the read-only Access Policies notice; group, template, preview and
      assignment facts/actions were absent from the live DOM.
- [x] Released owner Settings enabled the default-off feature and refetched to
      `Disable agent policy templates`; released Access then rendered the live
      group, membership, template, version, preview and assignment controls.
      Supported owner API restored opt-in Off after the proof.
- [x] Real PostgreSQL migration proof passed empty 97->96->97 preservation and
      populated rollback refusal with F09 rows/hashes preserved.
- [x] Cleanup revoked/removed both disposable agents, removed all live F09
      memberships/assignments/generated bindings, restored opt-in Off, deleted
      consumed bootstrap scratch and left shared services healthy.

Two destination resources remain intentionally because immutable template
versions protect them with `ON DELETE RESTRICT`. They are named F09 historical
evidence and are not active grants or live assignments; bypassing the FK to
force-delete them would violate D2/D9.

## Required redacted artifacts

- `walk-artifacts/F09/20260816T1159Z/provenance.md`
- `walk-artifacts/F09/20260816T1159Z/group-template-flow.md`
- `walk-artifacts/F09/20260816T1159Z/permission-and-ui.md`
- `walk-artifacts/F09/20260816T1159Z/rollback-and-cleanup.md`
