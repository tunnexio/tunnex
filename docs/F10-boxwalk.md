# F10 — Just-in-time agent access box-walk

Status: **SATISFIES** on exact source `e951927d13f82cea29d71c338c9303370f797392`.

The combined walk uses one exact committed F10 build on AWS DEV, the existing
healthy gateway/agent path, uniquely named disposable F10 state, and the F08
control-plane diagnostic. Cookies and other reusable secrets remain only in
mode-0600 scratch and never enter evidence.

## Acceptance

- [x] Record exact source/image labels, schema 98, service health, and a verified
      rollback bundle before any story mutation.
- [x] Confirm Enterprise unlock with organization opt-in Off; enabling through
      released Settings grants nothing and refetches the persisted state.
- [x] Create one accountable-human request for one agent, one immutable
      destination snapshot, one reason, and one bounded duration. Pending state
      creates no policy rule or compiled-policy change.
- [x] Approve once through the released owner workflow. Idempotent replay creates no
      duplicate request, event, rule, or audit row; a conflicting replay refuses.
- [x] Prove the ordinary expiring policy rule changes F08 Test Access from denied
      to allowed and uses the server-calculated approval expiry.
- [x] Prove reject and cancel create no rule; emergency revoke and automatic
      expiry remove only their exact rule and record human/system provenance.
- [x] Prove pending/approved requests block destination deletion with explicit
      impact, while terminal history survives a supported destination deletion
      using the immutable snapshot.
- [x] Prove suspend/revoke cannot retain or restore pending/approved JIT access.
- [x] Prove owner/admin and scoped-requester views, unrelated-member uniform
      refusal, released-DOM absence, and organization-switch clearing.
- [x] Prove migration empty 98->97->98 preservation and populated rollback
      refusal preserving request/events/rule expiry/compiled hashes.
- [x] Remove only disposable F10 live state, restore opt-in Off, erase secret scratch,
      and leave shared services/schema healthy.

The released owner mutation callers are the same typed endpoints exercised on
the wire; the exact released bundle's configured route suite is part of the
green `make web-gate`. The released member page was also inspected live after
authority withdrawal: it retained only the accountable requester's immutable
terminal history and rendered none of the create/approve/reject/revoke actions.

## Required redacted artifacts

- `walk-artifacts/F10/20260817T052930Z/provenance.md`
- `walk-artifacts/F10/20260817T052930Z/request-approval-flow.md`
- `walk-artifacts/F10/20260817T052930Z/terminal-lifecycle-and-permissions.md`
- `walk-artifacts/F10/20260817T052930Z/rollback-and-cleanup.md`
