# S7.5.5 box-walk — D5 exemption: bearer rider (method-keyed, same-subject contrast)

Live wire: `ubuntu@Tunnex-dev-vm`, api behind nginx, **enterprise build**, commit `fdff72a`.
Subject: `member@demo.tunnex.local`, org `01900000-…-001` (`org_enforces=t`).

Proves D5 (LOCKED): org MFA enforcement is keyed on the principal's **mint-time auth method**,
not the user or the org. A local-password session for an unenrolled user in an enforcing org is
GATED; a bearer credential for the **same user** is EXEMPT (the IdP/downstream-of-a-compliant-
session owns the factor). This is the exact property the story-end review caught as unproven, and
it was unobservable earlier while the casing brick denied everything.

## Credential provenance (why an "unenrolled-gated" user has a working bearer)

A gated session CANNOT mint a bearer — `cliAuthorize` is OFF the enrollment-gate allowlist by
design, so a gated user is 403'd there. The bearer here was minted in **Phase A while the member
was ENROLLED and un-gated** (full PKCE: login → enroll → confirm-flips-session-ungated →
`cli/authorize` → `cli/token`). Only THEN did Phase B disenroll the member (delete `user_totp`).
The credential survives disenrollment (it binds the identity, not the MFA state) — modelling a CLI
token minted while compliant, whose owner later falls out of MFA compliance. That is precisely the
case D5 exempts, and the sequence makes clear the exemption is not a way to bootstrap around the gate.

## Observed

Phase A — mint (member enrolled):

| step | request | HTTP |
|------|---------|------|
| A1 | POST /auth/login (password) | 200 (gated session) |
| A2 | POST /auth/mfa/enroll | 200 (secret) |
| A3 | POST /auth/mfa/enroll/confirm | 200 — session now UNGATED |
| A4 | POST /auth/cli/authorize (cookie, ungated, PKCE S256) | 200 (one-time code) |
| A5 | POST /auth/cli/token (public, code+verifier) | 200 — bearer `tnx_…` issued once |

Phase B — reset to `confirmed_totp=0`, then contrast (same user / org / op / moment):

| step | auth method | request | HTTP | body code | verdict |
|------|-------------|---------|------|-----------|---------|
| B1 | local-password | POST /auth/login | 200 | `enrollment_required=true` | gated session minted |
| B2 | local-password (cookie) | GET /organizations/{org}/devices | 403 | `mfa_enrollment_required` | **GATED** |
| B3 | bearer (`tnx_…`) | GET /organizations/{org}/devices | 200 | (none) | **EXEMPT** |

## Verdict

Same subject, same org, same non-allowlisted op, back-to-back — local-password GATED, bearer
EXEMPT. The discriminator is auth-method provenance alone → the gate keys on the principal's
immutable mint-time method (D5), not a route/header sniff. Wire-proven.

Scratch (TOTP secret, PKCE verifier, bearer token) stayed on the box — never committed.
