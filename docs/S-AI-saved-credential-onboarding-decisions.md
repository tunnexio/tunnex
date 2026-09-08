# Saved credential onboarding correction

2026-09-08, `ai-improvement`. User supplied evidence of applied Azure credentials named `azure` and an empty Existing Credentials selector before choosing a provider.

## Decisions

- Locked: offer usable saved credentials before a provider is selected. Choosing one also selects its provider. Once a provider is selected, filter credentials by that provider. Preserve pending/failed-key refusal.
- Locked: selecting saved credentials clears draft secrets and hides the upstream endpoint, credential name and API-key inputs. The saved connection supplies those values; never read its secret into the browser.
- Locked: successful real inference tests in both credential and model editors emit Sonner success feedback, explicitly identifying HTTP 200 and the tested model. An HTTP-200 envelope with `status: error`, a failed HTTP response, or a stale/cancelled request must never emit success. Keep persistent inline feedback.
- Locked: selected credential, provider, endpoint, model, mode and credential revision changes invalidate test success.
- Locked: tests must not change saved credentials, broaden a native key's model scope, or grant team access. No calls with the user's real saved key during verification; use synthetic fixtures.
- Pending, surfaced to user: the pinned serving engine filters stored keys by their existing model allowlist before honoring `x-bf-api-key-id`. Testing an additional unsaved model with a saved key requires a dedicated private-engine operation; do not temporarily widen or copy stored keys. Native source inspected at `core/bifrost.go` key selection and `transports/bifrost-http/lib/ctx.go`.

## Validation

Reproduce the provider-unselected saved-credential selector, stale draft clearing, HTTP-200 failure envelopes and stale test responses in component regressions. Typecheck and run the affected web suite. Any engine change requires both API editions, ownership/revision/refusal tests and actual pinned-engine wire proof; catalogue refresh is not inference proof.
