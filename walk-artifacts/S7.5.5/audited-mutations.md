# S7.5.5 box-walk — audited mutations (enrolled / recovery-code-used / admin-reset + notify)

Live wire: `ubuntu@Tunnex-dev-vm`, api behind nginx, **enterprise build**, commit `fdff72a`.
Subjects: member `…003`, owner `…002`, org `…001`.

## Observed

**PART 1 — `mfa.enrolled` + `mfa.recovery_code_used` (member):**
- Enroll ceremony (login→enroll→confirm) writes `mfa.enrolled`; confirm issues 10 single-use recovery codes.
- Fresh login (enrolled user) → `mfa_required=true` + challenge token (D6: challenge, not a session).
- `POST /auth/mfa/verify` with a **RECOVERY CODE** (not TOTP) → HTTP 200, session issued → `mfa.recovery_code_used`.

**PART 2 — `mfa.admin_reset` + Mailpit notification (owner resets member):**
- Owner (PermMfaManage) `POST /organizations/{org}/members/{member}/mfa-reset` → **HTTP 204**.
- Mailpit shows one message: **To=member@demo.tunnex.local, Subject="Your two-factor authentication was reset"**
  — the target is notified best-effort (a silently-reset factor by a compromised admin must surface to the owner).

**PART 3 — audit rows (`audit_logs where action like 'mfa.%'`):**

| action | actor_user_id | target_type | target_id |
|--------|---------------|-------------|-----------|
| mfa.admin_reset | `…002` (owner/admin) | user | `…003` (member) |
| mfa.enrolled | `…002` | user | `…002` (self) |
| mfa.recovery_code_used | `…003` (member/self) | user | `…003` |
| mfa.enrolled | `…003` | user | `…003` (self) |
| mfa.enforce_enabled | `…002` (owner) | organization | `…001` (from Leg A) |

## Verdict

All three mutations audited on the wire with correct actor/target framing: `admin_reset` records the
ADMIN as actor against the member as target (disenroll-only, never authenticates as them);
`recovery_code_used` records the member acting on self (a distinct security-signal from an enroll);
`enrolled` self-on-self. The admin-reset target notification is observed in Mailpit. `enforce_enabled`
(org-target) carried over from the enforcement-toggle leg.

Scratch (TOTP secrets, recovery codes) stayed on the box — never committed.
