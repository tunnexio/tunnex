# Approved AI UI improvements

Implemented after the user approved the ranked walk findings:

- JIT request state/agent filters and keyset Load more; complete agent inventory; scoped agent-detail navigation; requester cancellation including admins; required-reason rejection modal.
- Chat answer and token count first, expandable original response details.
- Accurate OAuth access-lease explanation and missing model-cost guidance without hiding usage totals.
- Links between provider setup, user groups and model examples; MCP setup sequence and policy-template explanation.
- Contract-specific non-chat curl examples, multipart transcription, speech file output, retained video idempotency key. Chat VPN example still uses dummy key; other operation examples explicitly require Tunnex authentication. No unconfigured model is represented as tested.

Verification: 127 test files / 1526 tests pass; typecheck and production build pass; git diff check clean. Two independent bounded reviews completed, findings folded and reviewed again. Browser local fixture verified rejection modal required reason and submit transition, model answer/details, operation example, missing-cost totals and MCP next-step navigation. Preview uses real components with development-only simulated transport; it does not contact providers or CP.

Preview: `pnpm --filter @tunnex/web exec vite --host 127.0.0.1 --port 5199`, then `/ai-ui-preview.html`. The development fixture is not part of the production entry.

## CP deployment

Product commit71ca8ebb deployed as tunnex-web:ai-mcp-71ca8ebb. Uploaded artifact SHA2569489900db0c0dd59bcc0467bd51e4803e5d36746fc6bb67066efa8c066c0319e verified on CP. Image manifest list27f2678e47af933d63177d6ebe6fa8d2d1b115549e7ca6a09dd3e8ead0a05203. Restricted rollback override: /home/ubuntu/tunnex/ai-mcp-fixes-20260911/rollback-before-ui-71ca8ebb.yml.

Web healthy; HTTPS healthzstatusok. Live My models retained single-org /ai/v1 and dummy-key VPN chat example. Browser chat returned HTTP200, exactUI_READY,86tokens; answer and usage appeared before collapsed Response details. No API, gateway, database or enforcement changes. No push, merge or release performed.
