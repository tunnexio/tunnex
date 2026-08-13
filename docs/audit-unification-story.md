# Audit-surface unification — story inputs (censused 2026-07-29, S11-6 + S11-7)

**Status: REGISTERED STORY, post-beta unless triggered.** Formerly two separate items — S11-6 (fourteen audit
helpers) and S11 D3.5 (a typed action registry). **They are the same refactor discovered twice** and are
merged here: the vocabulary cannot be typed cleanly while the helpers are fourteen, and the helpers cannot be
unified without touching every action string. Sequencing them means doing the same call sites twice with a
half-typed intermediate state in between; doing them together means ONE signature makes typing free.

**Scope: one helper, one typed vocabulary, one drift red.**

**Trigger: the next change to audit behaviour** (a new actor kind, a required field, a redaction rule, a
retention constraint) — because that change is what would otherwise have to be mirrored fourteen times.

## Why it isn't slice-sized (S11-7, measured not estimated)

The D3.5 attempt was reverted mid-conversion rather than committed half-applied. Replacing literals is
trivial (71 landed in one pass); making them TYPED is not, because the fourteen helpers have heterogeneous
signatures:

- `action string` params appear in varying positions and across multiple lines — a regex converts most and
  leaves a tail in `invites`, `mfa`, `ovpn`;
- **eight packages declare their own identifier `audit`** (a method or function), which collides with the
  package name and needs an import alias in exactly the packages the refactor touches most;
- `action` flows into `slog.String(...)` and sqlc struct fields expecting `string`, each needing a conversion
  at a different call depth.

That is surface, not difficulty — and it is direct evidence for the sizing: the fourteen-helper spread is
what makes even a vocabulary change awkward.

## The censused inputs

Measured by an AST census (parsing every non-test file under `internal/`), not by grep — and the census
caught its own inadequacy first: version one inspected call ARGUMENTS only, found 51 actions, and would have
passed while sixteen branch-selected literals survived. Extending it to assignments gave the real number.

- **68 distinct actions** across **72 sites**
- **14 audit-helper definitions** across **9 packages**: `policy` (`writeAudit`, `writeAuditAs`,
  `writeSystemAudit`), `tenancy` (2 + a bespoke `deactivate`), `mfa` (2), `sites` (2), `k8s`, `ovpn`,
  `invites`, `devices`
- **16 branch-selected literal pairs** (`action := "x.disabled"; if c { action = "x.enabled" }`) — incidental
  dynamism, convertible to constants; the vocabulary is CLOSED (no `fmt.Sprintf`, no concatenation, nothing
  data-derived)

## The complete vocabulary (68)


### `device` (10)

- `device.approved`
- `device.cancelled`
- `device.created`
- `device.health_blocked`
- `device.health_compliant`
- `device.health_noncompliant`
- `device.health_unblocked`
- `device.rejected`
- `device.revoked`
- `device.self_approved`

### `domain` (3)

- `domain.claim_created`
- `domain.verification_failed`
- `domain.verified`

### `group` (5)

- `group.created`
- `group.deleted`
- `group.member_added`
- `group.member_removed`
- `group.updated`

### `invite` (4)

- `invite.accepted`
- `invite.created`
- `invite.resent`
- `invite.revoked`

### `k8s` (4)

- `k8s.cluster_deregistered`
- `k8s.cluster_registered`
- `k8s.service_exposed`
- `k8s.service_unexposed`

### `machine` (2)

- `machine.credential_issued`
- `machine.credential_revoked`

### `member` (3)

- `member.jit_joined`
- `member.removed`
- `member.role_changed`

### `mfa` (5)

- `mfa.admin_reset`
- `mfa.enforce_disabled`
- `mfa.enforce_enabled`
- `mfa.enrolled`
- `mfa.recovery_code_used`

### `node` (4)

- `node.enrolled`
- `node.hub_priority_set`
- `node.revoked`
- `node.token_issued`

### `org` (12)

- `org.cidr_resized`
- `org.created`
- `org.deleted`
- `org.device_approval_disabled`
- `org.device_approval_enabled`
- `org.health_check_cleared`
- `org.health_check_set`
- `org.ovpn_disabled`
- `org.ovpn_enabled`
- `org.updated`
- `org.zero_trust_disabled`
- `org.zero_trust_enabled`

### `ovpn` (1)

- `ovpn.profile_exported`

### `policy` (6)

- `policy.grant_expired`
- `policy.grant_extended`
- `policy.rule_created`
- `policy.rule_deleted`
- `policy.rule_disabled`
- `policy.rule_enabled`

### `resource` (3)

- `resource.created`
- `resource.deleted`
- `resource.updated`

### `site` (3)

- `site.subnet_approval_refused`
- `site.subnet_approved`
- `site.subnet_removed`

### `sso` (1)

- `sso.config_updated`

### `user` (2)

- `user.deactivated`
- `user.reactivated`

## The drift red, when it is built

Per PROVE-A-GUARD-REJECTS and its S11-7 corollary: the red must reject the HARDEST shape, not the easiest —
a branch-selected assignment, not merely a call argument. The reverted implementation (an AST walk over
`internal/` flagging both `CallExpr` arguments and `AssignStmt` right-hand sides whose value matches the
lower_snake dotted action shape) is the reference; it was proven to enumerate all 68 before being reverted
with the rest of the attempt.

