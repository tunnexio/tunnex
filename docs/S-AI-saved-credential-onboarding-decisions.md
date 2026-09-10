# Saved credential onboarding correction

2026-09-08, `ai-improvement`. User supplied evidence of applied Azure credentials named `azure` and an empty Existing Credentials selector before choosing a provider.

## Decisions

- Locked: offer usable saved credentials before a provider is selected. Choosing one also selects its provider. Once a provider is selected, filter credentials by that provider. Preserve pending/failed-key refusal.
- Locked: selecting saved credentials clears draft secrets and hides the upstream endpoint, credential name and API-key inputs. The saved connection supplies those values; never read its secret into the browser.
- Locked: successful real inference tests in both credential and model editors emit Sonner success feedback, explicitly identifying HTTP 200 and the tested model. An HTTP-200 envelope with `status: error`, a failed HTTP response, or a stale/cancelled request must never emit success. Keep persistent inline feedback.
- Locked: selected credential, provider, endpoint, model, mode and credential revision changes invalidate test success.
- Locked: tests must not change saved credentials, broaden a native key's model scope, or grant team access. No calls with the user's real saved key during verification; use synthetic fixtures.
- Locked by explicit user reply: add the dedicated private-engine test operation for new models too. The engine resolves its own stored key, checks the expected key revision/name and endpoint, and forwards one bounded request to the existing installation-configured LiteLLM probe bridge. Only sanitized status/duration leaves the operation. This preserves the serving key's model allowlist and reuses the eight-mode SDK probe implementation. The control plane never receives the stored secret. The engine-to-bridge URL/token are installation configuration, never browser input.
- Locked: maintain a small extension against the exact upstream v2.0.0 source commit `9537b2fadf42af90eb34ed47d3d4252e1beff4a0`. Keep official unmodified artifacts available; the saved-key probe requires the extension and must fail clearly on older engines. Local preview uses the extended engine after isolated synthetic proof, preserving its existing data/configuration.

## Validation

Reproduce the provider-unselected saved-credential selector, stale draft clearing, HTTP-200 failure envelopes and stale test responses in component regressions. Typecheck and run the affected web suite. Any engine change requires both API editions, ownership/revision/refusal tests and actual pinned-engine wire proof; catalogue refresh is not inference proof.
