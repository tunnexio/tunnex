# S7.5.5 box-walk — downgrade-release (D2), both halves

Live wire: `ubuntu@Tunnex-dev-vm`, api behind nginx. This leg rebuilds the api **open**
(`go build -tags ""`) from the same source — a real edition downgrade — with the org's enforce
flag left ON in the DB.

## Precondition

`org_mfa.enforce = true` for org `…001` PERSISTS across the downgrade (the flag is data, not code).

## Observed (open build)

**Half (a) — the gate EVAPORATES.** Unenrolled member (`confirmed_totp=0`) in the still-"enforcing" org:

| step | request | HTTP | signal | verdict |
|------|---------|------|--------|---------|
| a1 | POST /auth/login | 200 | `mfa_required=false`, NO `enrollment_required` | no gated session — gate not engaged |
| a2 | GET /organizations/{org}/devices | 200 | no `mfa_enrollment_required` | reaches a non-allowlisted op UNGATED |

**Half (b) — enrolled user STILL challenged.** Owner (`confirmed_totp=1`):

| step | request | HTTP | signal | verdict |
|------|---------|------|--------|---------|
| b1 | POST /auth/login | 200 | `mfa_required=true` + `challenge` | self-enrolled MFA still enforced at login |

## Verdict

Downgrade RELEASES enforcement — it does not break MFA. On the open build the enforce flag persists
but is IGNORED (the member reaches everything ungated; no error, no lock), while a user's OWN enrolled
TOTP still challenges at login. This is the D2/S7.5.3 downgrade-releases-enforcement law made concrete:
edition loss lifts the org-level compulsion, leaving individual enrollment (open in all editions) intact.
The "enrolled-user-still-challenged" half is the important one — it proves secrets SURVIVE and keep
WORKING, not merely that the gate is gone.

Box left on the OPEN build after this leg (restore with `TUNNEX_BUILD_TAGS=enterprise docker compose
up -d --build --no-deps api`).
