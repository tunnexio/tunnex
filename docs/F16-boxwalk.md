# F16 — argument controls, rate limits, and step-up approval box-walk

## Local proof

- [x] The F16 API, proxy, and UI focused tests pass; the web typecheck, full
  web test suite, and production web build pass.
- [x] Invalid argument-control JSON is refused by the operator UI before a
  policy write.
- [x] The proxy returns distinct fail-closed refusals for a denied tool,
  disallowed arguments, a rate-limited call, and a missing step-up permit.

## Live wire proof — completed 2026-08-21

The existing disposable CP and existing managed agent were used. The proxy
remained loopback-only and routed only to the public DeepWiki MCP endpoint.
No private repository, OAuth credential, token, or raw argument body was
stored in the CP.

1. In **AI agents → MCP tool policy**, the operator configured the existing
   `DeepWiki · read_wiki_structure` F14 allow with a rate cap and step-up
   approval. The policy was versioned and the runtime received the projection.
2. A `tools/call read_wiki_structure` through the agent's loopback proxy
   returned HTTP `403` with `MCP tool requires step-up approval`. The CP
   recorded one pending request containing only the catalog identity and
   request digest.
3. The operator clicked **Approve once** in the CP UI. The request state became
   `approved`; the browser did not receive a permit, raw arguments, or provider
   credentials.
4. Retrying the identical request consumed the permit. The first forwarded
   attempt exposed the provider's required response-negotiation header and
   returned its HTTP `406`; the permit nevertheless became `consumed`, proving
   one-use state is committed before the upstream round trip.
5. A second fresh UI approval followed by the same request with DeepWiki's
   required `Accept: application/json, text/event-stream` header returned HTTP
   `200` and a real public `facebook/react` structure result. Its corresponding
   CP record became `consumed`.
6. The walk found an initial schema constraint that rejected the
   `approved → consumed` transition while retaining the approval timestamp. A
   compatibility migration corrects the constraint; live API startup applied it
   cleanly and the subsequent two consumed records prove the repair.
7. The policy was restored after the walk to its original F14 shape: only
   `read_wiki_structure` remains allowed, with no F16 rate cap, argument
   constraint, or step-up requirement. All CP services were healthy afterward.
