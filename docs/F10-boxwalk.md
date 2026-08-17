# F10 — Just-in-time agent access box-walk

Status: **IN PROGRESS**.

The combined walk uses one exact committed F10 build on AWS DEV, the existing
healthy gateway/agent path, uniquely named disposable F10 state, and the F08
control-plane diagnostic. Cookies and other reusable secrets remain only in
mode-0600 scratch and never enter evidence.

## Acceptance

- [ ] Record exact source/image labels, schema 98, service health, and a verified
      rollback bundle before any story mutation.
- [ ] Confirm Enterprise unlock with organization opt-in Off; enabling through
      released Settings grants nothing and refetches the persisted state.
- [ ] Create one accountable-human request for one agent, one immutable
      destination snapshot, one reason, and one bounded duration. Pending state
      creates no policy rule or compiled-policy change.
- [ ] Approve once through the released owner inbox. Idempotent replay creates no
      duplicate request, event, rule, or audit row; a conflicting replay refuses.
- [ ] Prove the ordinary expiring policy rule changes F08 Test Access from denied
      to allowed and uses the server-calculated approval expiry.
- [ ] Prove reject and cancel create no rule; emergency revoke and automatic
      expiry remove only their exact rule and record human/system provenance.
- [ ] Prove pending/approved requests block destination deletion with explicit
      impact, while terminal history survives a supported destination deletion
      using the immutable snapshot.
- [ ] Prove suspend/revoke cannot retain or restore pending/approved JIT access.
- [ ] Prove owner/admin and scoped-requester views, unrelated-member uniform
      refusal, released-DOM absence, and organization-switch clearing.
- [ ] Prove migration empty 98->97->98 preservation and populated rollback
      refusal preserving request/events/rule expiry/compiled hashes.
- [ ] Remove only disposable F10 state, restore opt-in Off, erase secret scratch,
      and leave shared services/schema healthy.

## Required redacted artifacts

- `walk-artifacts/F10/<run>/provenance.md`
- `walk-artifacts/F10/<run>/request-approval-flow.md`
- `walk-artifacts/F10/<run>/terminal-lifecycle-and-permissions.md`
- `walk-artifacts/F10/<run>/rollback-and-cleanup.md`
