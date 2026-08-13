# S7.5.5 box-walk — grandfather leg (RE-RUN after the walk-found gate brick)

Live wire: `ubuntu@Tunnex-dev-vm`, api behind nginx (`http://localhost` → nginx:80 → api),
**enterprise build** (`go build -tags "enterprise"`), commit `fdff72a`.

## Why this is a re-run

The first grandfather attempt (on `f44cb1b`) found a real defect: a MFA-enforcement-gated
member got `403 mfa_enrollment_required` on EVERY op — including the allowlisted `/auth/me`
and `/auth/mfa/enroll` — so the grandfather path was fully **bricked** (could not enroll to
escape). Root cause: `enrollmentGateAllow` was keyed in source-yaml camelCase while
`api.GetSwagger()` carries oapi-codegen's exported PascalCase operationIds → zero matches.
Fixed in `fdff72a` (allowlist keyed on the embedded names; self-arming test de-tautologized;
permanent full-chain `NewRouter` red added). See `docs/S7.5.5-decisions.md` → "Walk-found
defect — the enrollment-gate BRICK + tautological guard".

## Precondition (DB)

`member@demo.tunnex.local` — role member, org `01900000-…-001` (Demo Organization),
`org_enforces=t`, `confirmed_totp=0` → gated by construction.

## Observed (member session, one cookie jar, gated → enroll → confirm)

| # | request | HTTP | body signal | verdict |
|---|---------|------|-------------|---------|
| 1 | POST /auth/login | 200 | `enrollment_required=true`, `mfa_required=false` | D8 gated session minted (cookie set, not a challenge) |
| 2 | GET /auth/me (allowlisted) | 200 | no error code | **FIX** — was 403 `mfa_enrollment_required` |
| 3 | GET /organizations/{realOrg}/devices (non-allowlisted), pre-enroll | 403 | `mfa_enrollment_required` | gate HOLDS default-deny for a gated user |
| 4 | POST /auth/mfa/enroll (allowlisted) | 200 | secret returned (32 chars) | **FIX** — was 403 |
| 5 | client-side only: compute RFC-6238 TOTP from the step-4 secret (NO wire call) | n/a | 6 digits | not an API request — kept in the numbering so 4→6 has no gap |
| 6 | POST /auth/mfa/enroll/confirm | 200 | `recovery_codes` issued | valid code arms MFA; gate flips |
| 7 | GET /organizations/{realOrg}/devices (same op), post-confirm | 200 | no `mfa_enrollment_required` | gate RELEASED on confirm |

## Verdict

The exact bricked leg is GREEN end-to-end on the live wire: allowlisted escape ops reachable
while gated (2, 4), non-allowlisted held typed (3), confirm-in-the-same-session releases the
gate (7). Default-deny holds; the grandfather can self-rescue. Brick dead.

Scratch (TOTP secret, recovery codes) stayed on the box — never printed in full, never committed.
