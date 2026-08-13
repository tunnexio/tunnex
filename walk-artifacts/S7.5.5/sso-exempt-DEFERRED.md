# S7.5.5 box-walk — SSO-exempt half: DEFERRED (named trigger), not dropped

## Timebox check (per the founder's ~15-min rule)

Verified the box-side SSO wiring for the enforcing Demo org (`01900000-…-001`):

| signal | result |
|--------|--------|
| sso_configs row | ONE row, provider=`google`, enabled=t, **tenant_id empty**, client_id `demo-ent…` (seed STUB — fake id, no real secret) |
| microsoft/Entra config | **absent** — `startSsoLogin microsoft` → 404 `sso_not_configured` |
| Entra network reachability | `login.microsoftonline.com` HTTP=200 (network fine) |

The S7.5.2 live-Entra setup is NOT present in this stack's DB (re-seeded / different stack). The
network is fine; what's missing is a live `microsoft` config — a real Entra app registration
(client id + sealed secret + tenant), redirect URIs for this box origin, and a test user with known
credentials. Standing up that is exactly the box-side config archaeology the timebox rule says NOT
to burn walk-session time on.

## Disposition: DEFER with a named trigger

**SSO-exempt wire proof → deferred to the S7.5.2b / SSO-walk infra window** (a named event, not a
calendar clock). The property (an SSO-minted principal in an enforcing org logs in UNGATED, while a
local-password user is gated) is NOT dropped.

## SUBSTITUTE (recorded — SUBSTITUTES ≠ SATISFIES)

Until the trigger, the SSO-exempt property rides:
1. **Unit pin** `TestEnrollmentGateAuthMethodExemption` — an SSO-minted principal passes the gate
   ungated; a bearer principal passes; a local-password unenrolled principal IS gated. Absolute.
2. **Mint-seam re-review** — the SSO session stamps `AuthMethod = AuthSSO` at the SSO mint seam
   (`sso_handlers.go` `Create(ctx, userID, authctx.AuthSSO)`), immutable thereafter.
3. **Wire-proven shared mechanism** — the bearer rider (`bearer-exempt-contrast.md`) proved ON THE
   WIRE that the gate keys on the principal's mint-time auth method (local GATED vs bearer EXEMPT,
   same subject/org/op). SSO and bearer share that exact mechanism; only the SSO-mint→`AuthSSO`
   stamping is unproven on the wire.

**Wire proof OWED at the trigger** — completing an interactive Entra login on the wire and observing
the resulting SSO session reach a non-allowlisted op ungated, contrasted against the same user's
local-password session gated.
