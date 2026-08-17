# Terminal lifecycle and permissions

- Separate pending requests were rejected and cancelled. Both remained
  rule-less; the sole approved request's rule count stayed one.
- Emergency revoke transitioned approved requests to `revoked` and withdrew
  only their exact rules.
- A five-minute approved request transitioned automatically to `expired`; its
  rule was absent afterward and terminal history remained readable.
- Suspending the connected disposable agent transitioned its approved request
  to `revoked`, removed the exact rule, stopped the runtime cleanly, removed the
  interface and left restart count zero.
- Resume plus an explicit runtime service start restored the agent tunnel but
  did not restore JIT access: Test Access remained denied with
  `no_matching_grant`.
- After managing-group authority was removed, the member destination picker
  returned uniform 403 `forbidden`. The accountable requester could still read
  its own terminal request history.
- Released member DOM was inspected on the exact deployed web image. It showed
  F10 Off and only that requester's immutable terminal history; no create,
  approve, reject or revoke actions were present.
- With every request terminal, supported destination deletion returned 204.
  Request detail still returned the immutable destination id and name snapshot.
