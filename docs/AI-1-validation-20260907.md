# AI gateway foundation validation — 2026-09-07

Branch: `ai-improvement`, based on main `5199b62d15c5498bc8ede58703b9d5af5aa45c23`.
This is a local implementation checkpoint, not complete epic/beta acceptance.
No push, PR, merge, release or cloud operation. Final validation did not enable
paid smoke; earlier authorized provider calls are recorded in AI-0 evidence.

## Completed checks

- Native generated-contract drift: sqlc 1.31.1; oapi-codegen 2.4.1 for API and CLI;
  openapi-typescript 7.4.4; RBAC and token generators. All 49 before/after file
  hashes identical. This is a native equivalent of the codegen drift gate; the
  default Docker context is stopped and current repository bind mounts are not
  available inside the running Colima VM.
- AI isolated PostgreSQL migrated to139, dirty=false. All database commands
  verify COMPOSE_PROJECT_NAME=tunnexai0907, container tunnexai0907-postgres-1 and
  network tunnexai0907_default on context colima-tunnex-sso-review. Existing SSO
  resources were not modified.
- Final pinned native-engine, adapter, credential and encrypted-key race suite:
  `go test -race -count=1 ./internal/aigateway`, PASS39.051s, no paid smoke enabled.
- Current HTTP route/auth census focused race run: PASS6.683s. Both editions'
  actual socket/database AI routes passed, including incremental delivery and
  session/cross-tenant refusal.
- Credential retention and actual PostgreSQL lock-contention revocation tests:
  open PASS8.252s, enterprise PASS5.642s. MaxConns=1 shared-transaction regression
  and envelope substitution/tamper tests pass.
- Full open API suite: `go test -p 1 ./...`, PASS. The initial attempt exposed
  an unmigrated legacy fixture database; after its isolated migration the full
  auth census found two ordering defects, fixed and re-run successfully.
- Full enterprise API suite: `go test -p 1 -tags enterprise ./...`, PASS.
- API open and enterprise `go build ./...`: PASS.
- Node Linux runtime gate in a dedicated disposable container with isolated
  NET_ADMIN: `apk add --no-cache git openvpn nftables iptables` followed by
  `go test -count=1 ./...`, all14 packages PASS. No host mount/network or database.
  Separate Linux/amd64 compile also passed; it is not substituted for the runtime run.
- Web:112 Vitest files /1300 tests PASS; `tsc -b` PASS; Vite production build PASS.
  Existing bundle-size advisory is not a failure. AI setting tests include
  unavailable enable/disable, server response truth, network failure and stale
  reads/writes across org changes.
- Browser fixture rendered unavailable, ready, enabled and load-error states;
  clicking enable reflected the fixture server response. This is component visual
  verification, not user visual approval or a live installed gateway walk.
- Metadata-only native engine proof: scoped request/token stats persisted while
  unique prompt/response markers were absent from logical and raw SQLite log
  storage. Scope: synthetic non-streaming success, not every provider/error path.
- Independent review plus re-review covered identity/persistence, folded cleanup,
  error envelopes and key bindings. No additional actionable finding in those
  bounded scopes. Engine-author review is self-review, not an independent finder.

## Remaining acceptance

- AI-2 team-composition disposition and its final OpenAPI/persistence contract.
- Production policy resolver/server composition, desired/applied reconciliation,
  scoped historical team usage and monetary-policy unknown-price refusal. Native
  client primitives and budget qualification are not those completed integrations.
- Full customer install, upgrade/rollback, provider-secret rotation and examples,
  Helm integration, real installed team-policy/accounting walkthrough, public web
  docs and final beta matrix. The optional Compose overlay is only statically
  validated; no Linux installation or nginx runtime parser proof claimed.
- Required exact-head remote CI has not run. Helper/client gates are absent in
  this core checkout after client extraction; any required external client CI
  must be verified on its repository when the candidate is submitted.

Next action: disposition one explicit AI team per agent versus multi-group
intersection in `S-AI-2-decisions.md`, then implement the frozen shared contract.
