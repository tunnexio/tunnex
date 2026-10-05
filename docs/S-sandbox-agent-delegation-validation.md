# Source validation and handoff

Historical decision record. Later integration is recorded in S-sandbox-change-coverage.md and S-sandbox-portable-runtime-decisions.md. This paper does not authorize live actions or assert that earlier pending states still describe current source.

Isolated worktree: `<preserved-local-worktree>`, branch `story/sandbox-agent-delegation`, committed foundation base `9b5d17d48fe2380c85488831de32ca210c13797f`. Initial literal local main had no sandbox core; parent explicitly corrected the integration base. No foundation cherry-picks or main edits.

Passed with `GOFLAGS=-mod=readonly`, task-local Go cache, race detection and disposable databases on existing local PostgreSQL fixture server:

- Final full sandbox suite, open edition:221.145s.
- Final full sandbox suite, enterprise edition:219.906s.
- Open and enterprise focused real PostgreSQL delegation tests: valid bounded grant/create/read/action; same-key replay and changed-intent conflict; grant quota; generation/stale-generation; forbidden TTL/template/network/skill escalation; cross-owner/org/node rejection; grant/credential revocation; expiry, owner reassignment, membership removal and organization opt-out; runtime authentication effective-deny before sweep; atomic audited generation withdrawal; human instance isolation; offline network retention and qualified cleanup; external-start revocation and expiry races. Additional cross-grant read/withdrawal isolation and machine idempotency namespaces passed both editions (open6.873s, enterprise7.115s with expiry race).
- Focused HTTP/RBAC tests: human-only opt-in/issuance/revocation boundary, body-derived ownership rejection, machine catalog boundary, legacy human provisioning and existing generated lifecycle routes. Final HTTP/RBAC1.629s/0.639s.
- Both API edition builds and CLI build.
- CLI lifecycle and existing bootstrap security tests1.476s; lifecycle wrapper preserves supplied retry key/generation, uses explicit existing machine bearer and refuses human credentials/cookies.
- `go vet` sandbox/HTTP/RBAC packages; formatting and `git diff --check`.

The first broad regression attempt identified a downgrade test that needed to unwind0180; that test is fixed and passed. The broad HTTP package run was not green: unrelated existing tests connected directly to an unmigrated shared fixture admin database and sessionless PUT validation assertions failed for sandbox catalog/setup and cross-gateway settings. These results are not claimed as full API gates. The sandbox fixture suite always creates/migrates/drops independent child databases.

Parent integration remains required: merge OpenAPI overlay, implement generated strict wrappers or deliberately dispatch the tested adapter, regenerate Go/TS/CLI/RBAC artifacts, and run combined generation/route gates after saved keys0179 and runner integration. No router/OpenAPI/generated files were edited here under the parent ownership agreement; the raw adapter alone is not registered in the normal router. Existing lifecycle machine calls fail closed without explicit current delegation. See `S-sandbox-agent-delegation-integration.md` and `S-sandbox-agent-delegation-openapi.yaml`.

No push, deployment, cloud provisioning, live credentials, live grants, worker enrollment or resource-cap changes. Tests use synthetic credentials and fully discarded databases. Live activation requires separate approval of the exact existing owned machine credential, organization opt-in and bounded grant, plus the separately qualified runtime. Cleanup is pending until actual provider/network withdrawal; offline runners cannot receive revocation until connectivity returns, and absolute local TTL remains the bound. These source tests substitute for, and do not satisfy, a live wire proof.
