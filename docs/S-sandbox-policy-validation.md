# Durable sandbox identity and bounded static policy: local evidence

2026-10-02, isolated branch story/sandbox-foundation; baseline main f6d4945.

Implemented: migration166 adds distinct sandbox/template records, immutable create intent, one-to-one same-org/creator sandbox peer binding, default-off organization enablement, proposed quotas, enforcing-mode admission and guard against switching to blanket mesh before cleanup. Store operations recheck active current human role sets, verification and forced-password-change status; creator-scoped idempotency hashes, transactional quota reservations, generation CAS and redacted audit entries. Admin access is an explicit separate permission. Current static user/group grants are intersected with requested scope and immutable template limits by the normal policy compiler. Disablement, expiry, desired stop/delete or membership loss removes projection. Typed SQL and RBAC artifacts regenerated using repository tools.

Passed:
- Four real PostgreSQL17 disposable-database tests under race detection: concurrent idempotency/quota; ownership, cross-org and generation refusal; immutable identities/templates and deferred peer binding; current-policy/template withdrawal; opt-in, verification/role and mesh-mode refusal; SQL downgrade refusal with existing template state and successful empty downgrade in rolled-back transaction.
- sandboxscope, policy, rbac and sandboxes package race tests.
- Existing managed-agent access and agent-template PostgreSQL regression cases on task-owned local PostgreSQL.
- HTTP, devices and database package regressions (DB integration cases without explicit DSN skip).
- Open and enterprise server builds; go vet for changed packages; formatting and git diff --check.

Initial HTTP regression invocation could not bind httptest loopback listeners inside the sandbox; approved local-socket invocation passed. PostgreSQL uses cached postgres:17-alpine, task-owned container tunnex-sandbox-feature-db-20261002, loopback127.0.0.1:55482 and tmpfs. Each integration case creates/drops its own database; no existing services/pilot used. No private credential files read.

Limits: supported delegation is static IPv4 CIDR/protocol/ports from user/group resource and site-destination grants. Dynamic FQDN/Kubernetes, IPv6 and explicit deny semantics are not introduced. Conservative admission refuses tuple-union coverage. Unit/DB evidence is not packet enforcement. Policy delivery deadlines, runtime network isolation, ingress SSH authorization, enrollment/readiness, cleanup, public routes/UI and optional skills remain unfinished. Store methods are internal and provisioning is default-off. Published release artifacts and an independent story-end review remain unverified; no production-readiness claim.

Follow-on peer separation: human roster/approval count queries select kind=human; generic device lifecycle and mode controls and human posture reporting refuse sandbox peers. Gateway/offboarding queries retain all kinds. Real PostgreSQL human and AI Agent roster queries exclude the enrolled sandbox; normal device/HTTP regressions pass.
