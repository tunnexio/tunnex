# Approved AI UI improvements

Implemented after the user approved the ranked walk findings:

- JIT request state/agent filters and keyset Load more; complete agent inventory; scoped agent-detail navigation; requester cancellation including admins; required-reason rejection modal.
- Chat answer and token count first, expandable original response details.
- Accurate OAuth access-lease explanation and missing model-cost guidance without hiding usage totals.
- Links between provider setup, user groups and model examples; MCP setup sequence and policy-template explanation.
- Contract-specific non-chat curl examples, multipart transcription, speech file output, retained video idempotency key. Chat VPN example still uses dummy key; other operation examples explicitly require Tunnex authentication. No unconfigured model is represented as tested.

Verification: 127 test files / 1526 tests pass; typecheck and production build pass; git diff check clean. Two independent bounded reviews completed, findings folded and reviewed again. Browser local fixture verified rejection modal required reason and submit transition, model answer/details, operation example, missing-cost totals and MCP next-step navigation. Preview uses real components with development-only simulated transport; it does not contact providers or CP.

Preview: `pnpm --filter @tunnex/web exec vite --host 127.0.0.1 --port 5199`, then `/ai-ui-preview.html`. The development fixture is not part of the production entry.
