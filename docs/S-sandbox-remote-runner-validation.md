# Remote runner source validation ledger

Historical decision record. Later integration is recorded in S-sandbox-change-coverage.md and S-sandbox-portable-runtime-decisions.md. This paper does not authorize live actions or assert that earlier pending states still describe current source.

Worktree: <preserved-local-worktree>; branch story/sandbox-remote-runner; integration baseline 9b5d17d. Owns only new internal/sandboxrunner files and this story's documentation. No migrations (0181 remains unused), public API/OpenAPI/schema/router/generated files, store.go, account-key UI/API or agent caller gate changes.

Implemented: exact verified TLS1.3 peer URI checks; operator certificate configuration; outbound HTTPS poll/reply client; one pending broker call with deadline/cancellation and stable redelivery ID; 64KiB control payload limits; durable command identity/reply replay and bounded record retention; durable immutable <=900s local leases, idempotent expiry callback/retry and expiry receipt. No CP provider fallback exists in this package. The runtime owner must serialize lease/command operations and fence the exact workload in its idempotent callbacks. Local expired receipts do not assert canonical peer withdrawal or release addresses.

Passed: focused package race tests in both editions, covering capacity, unverified/wrong-peer/TLS-version rejection, stable redelivery, replies, cancellation, durable replay/conflicting identity and immutable offline expiry retry. All API cmd packages compile in both editions. git diff --check passed. No dependency/module changes.

Remaining acceptance: actual TLS socket fixture (current peer tests exercise verified connection-state boundary), runtime RPC adapter and configuration, poll loop/expiry supervisor wiring, certificate enrollment/revocation tooling, exact helper/gateway bindings, resource/IO/log enforcement, remote health/admission status, crash-before-reply fixture and complete remote wire qualification. No existing local Unix worker path changed. No resources provisioned; approved EC2 launch waits for integrated readiness. This is a source foundation, not a completed external runner product or live proof.

## Runnable runtime slice

Now wired: APIWorkerConfig.Remote starts a dedicated private-IP mTLS broker and returns the existing WorkerRPCClient over the broker transport, without local fallback. Remote runtime mode initiates the pinned HTTPS client and retains the existing exact-binding dispatch; no local API socket is created. New offline enrollment command writes protected short-lived endpoint certificates. Offline expiry supervisor persists immutable leases before authorization, verifies exact provider identity and locally removes network/stops execution, preserving canonical cleanup authority and assets. Activation commands cannot start after expiry and receive that absolute context deadline.

Passed after wiring: both-edition focused race suites including actual loopback TLS API-RPC → broker → remote-runtime dispatch → reply, CheckBinding, authorization and durable lease creation; wrong runner certificate rejection; foreign offline-fence rejection, stop and idempotent retry. Linux/amd64 server, runtime and enrollment command builds passed in both editions. Temporary fixture enrollment only, no live credentials. Existing local-worker focused tests pass. PostgreSQL-backed tests that require configured fixture were not run in this wiring slice; no schema/store changes.

Live blocker: new runner gateway conflicts with existing same-gateway terminal and exact historical reservation bindings. Parent must disposition the terminal/enrollment and reservation-preservation source seams before activation. No new EC2 provisioned. Remaining wire acceptance includes scoped enrollment/config installation, resource/IO/log limits, actual new-host helper/gateway/private SSH/default SFTP, local expiry while CP unavailable, reconnection/canonical withdrawal/address release and CP resource/latency samples. 24h control certificates require explicit rotation; automated renewal is not implemented. This is runnable local source, not remote-host qualification.

Certificate lifecycle source now closes routine24h loss: actual mTLS fixture verified controller renewal, authenticated runner renewal, public certificate persistence/restart and explicit revoked-broker denial, both editions with race detector. CA key is generated only in disposable test fixtures; no live enrollment generated. Root lifetime365days, leaves24h, renewal at12h remaining; offline expiry beyond credential life stays fail-closed with operator recovery. Topology/source/access proposal is S-sandbox-remote-topology-proposal.md; no routing source or live setting has yet been changed for that proposal.

## Combined integration checkpoint (2026-10-04)

Integration HEAD b7f1298 on story/sandbox-remote-runner includes saved-key source c0e82d9/f559510 and delegation source445681a/b7f1298 (original commits422ed08/835841b/a046eee/7959c6f). Routing181, generated delegation handlers and regenerated API/CLI/TS/RBAC/sqlc are currently uncommitted while combined validation runs.

Focused race tests passed in both editions: actual generated delegation administration routes, human authorization before validation, server-derived owner/org and rejected malformed/owner-injected requests; remote persistent/private/distinct binding validation; PostgreSQL idempotency and immutable route pins; synthetic remote launch/Ready, exact /32 TCP22 grants on both gateways, actual site-less served desired-state corridor, stale terminal ACK refusal, stopped-state withdrawal and confirmed cleanup while historical reservation remains pending. This uses fake provider/network effects and does not establish new-host wire connectivity. Pure scoped-graph and policy placement race suites passed both editions, including unrelated site/hub exclusion. Web typecheck passed with Node24.21.0; saved-key, skills, creation and connection UI tests passed45/45.

The previously reported same-gateway source blocker is resolved in admission/start, orchestrator durable authorization, bootstrap placement, two-gateway policy convergence and topology-loading seams. Broader combined race suites and command/CLI builds are still running; results are in <preserved-local-artifact> and <preserved-local-artifact> Do not claim complete qualification until results and native builds pass.

The exact EC2 and scoped gateway link bundles are now user-approved. No instance, live peer, route, certificate, key import, agent grant or deployment has been created/applied during this source integration. Source-ready gate remains, followed by remote-host WireGuard/SSH/default SFTP, restart/expiry/canonical cleanup, resource and latency qualification. Earlier paragraphs describe historical stages; this checkpoint supersedes their unused-migration, no-router integration and pending-access statements.

## Final source gate checkpoint (2026-10-04)

Code content tip: `400dba4051b00d1948a607d4792468097fced290`; isolated branch `story/sandbox-remote-runner`, baseline `9b5d17d`. Integration is committed in `177bf90`, source-gate/authentication corrections in `70a609c`, and the bootstrap consumption guard in `400dba4`. Account public-key selection, configurable inert skills, explicit owned-machine delegation and scoped remote execution are integrated. The original checkout, live foundation and immutable historical reservation remain unchanged.

The final source corrections authenticate anonymous sandbox/key/scoped-routing requests before schema validation, retain the explicit human delegation-admin gate, account for the existing fifth CrossGatewayGraph seed, register only the three owned SSH execution-fixture reads in the web census, and remove the UI em dash. Standalone fixture/runner/probe/enrollment commands are explicitly classified outside the API runtime image. Both existing workflow classifiers now recognize the embedded image-profile JSON as a Go compile input; no workflow was dispatched. The node gate mounts the repository root so its existing helper contract reads the real `deploy/sandbox` specification.

Bootstrap token consumption now requires both the token hash and the organization already derived by the hash-bound bootstrap lookup. Caller-provided owner/org/gateway fields remain overridden by that identity. The PostgreSQL regression attempts consumption under another organization, expects no rows, then proves the same token remains usable for exactly one legitimate concurrent redemption. This preserves the existing single-use bootstrap protocol and adds an explicit SQL tenant boundary.

| Check | Result and evidence |
| --- | --- |
| Complete sandbox, gatewaymesh and sandboxrunner race suites, both editions | Passed; `<preserved-local-artifact>` |
| Corrected query lint, bootstrap/enrollment and remote placement race checks, both editions | Passed; `<preserved-local-artifact>` |
| Command packaging/embed census, both editions | Passed; `<preserved-local-artifact>` |
| Complete node dataplane gate | Passed after correcting the repository mount; `<preserved-local-artifact>` |
| Full web test suite | Passed: 150 files, 1,840 tests, two expected failures; `<preserved-local-artifact>` |
| Web typecheck and production build | Passed; `<preserved-local-artifact>`, `<preserved-local-artifact>` |
| Generated-code drift | Passed on committed SQL output; `<preserved-local-artifact>`; token generation had separately passed with no token-source changes |
| CLI tests, both editions | Passed; `<preserved-local-artifact>` |
| Native Linux/AMD64 validation artifacts | Go 1.26.8 server/runtime/enrollment builds passed both editions; servers refreshed after the token guard and confirmed x86-64; `<preserved-local-artifact>`, `<preserved-local-artifact>` |
| Complete standard API build/test gate, both editions | Both editions built successfully; both complete standard test runs failed only in `internal/ipsec` on frozen code tip `400dba4`; every other package passed; `<preserved-local-artifact>` |

Host Go 1.27.1 runs use `GOFLAGS=-mod=readonly`. The complete standard API gate matches the repository's ordinary non-race test mode; changed sandbox/routing/transport paths also have the separate full race proof above. Each edition receives a new database migrated through 0181. The replacement local fixture is `tunnex-runner-source-db-20261004`, loopback `127.0.0.1:55484`, capped 2 GiB temporary data storage; credentials stay in subprocess memory and are not recorded here. These source/fixture checks do not substitute for host wire qualification and do not establish remote SSH, runtime isolation on a new AMI, cleanup convergence, or startup latency.

Superseded runs are retained honestly: the initial broader harness pointed old HTTP/policy helpers at an unmigrated fixture and was corrected; a migration-down fixture ordering error was also corrected before the combined sandbox pass. Later runs lost the shared fixture when its 256 MiB data tmpfs filled. That shared container was left untouched, and no shared image/volume/cache pruning was performed. The first complete race run found the command census and bootstrap query-lint gaps above, then loaded mixed generated/source types during the correction (`ConsumeSandboxBootstrapTokenParams` undefined in its previously loaded dependency graph). It was intentionally stopped, exit 130, and supplies no complete-suite pass/fail conclusion for the stable code tip. The standard full gate is a fresh run of the committed source. The initial full web run's census/copy failures were corrected; its unrelated AI-provider retry test passed isolated and in the final full run.

The stable full API runs in both editions failed only in `internal/ipsec`: provider creation/rotation/delivery tests report `IPsec connection unavailable`, and `TestProviderGuardsPreserveWireGuardNoopsAndCleanup` reports missing `cross_gateway_clients_enabled` (SQLSTATE42703). IPsec source/queries are unchanged between `9b5d17d` and `400dba4`; the two representative failures were independently reproduced on frozen baseline `9b5d17d` in both editions, as recorded below. All other packages completed successfully in both editions. No IPsec fixes, test exclusions or schema workarounds were added.

The source stage retained API-owned credentials and a dedicated rootless worker/helper boundary. Its historical native acceptance and baseline failures are separate from the final combined source checks. Generic installation now uses the configurable offline installer; earlier host-specific blueprints and launch receipts remain outside the publishable tree.

### Native deployment artifacts and acceptance disposition

The complete six-binary runner bundle was built from a frozen archive of exact
`400dba4` with Go 1.26.8, Linux/AMD64, CGO disabled and offline readonly public
module caches. All six are static ELF64 x86-64 and passed SHA256 verification.
The bundle contains node, namespace helper, SSH probe, sandbox bootstrap,
sandbox runtime and offline enrollment; total binary content is 41,198,540 bytes.
Public provenance: `<preserved-local-artifact>`,
`SHA256SUMS`, `elf-evidence.txt` and `go-build-metadata.txt`. No private source
configuration or credential files are included. Existing Minimal/Python/Node
archives separately match the three approved OCI configuration digests, AMD64
and uid/gid 1001:1001; none has been loaded on a new host in this source stage.

The required affected sandbox, routing, authentication, generated API, node and
web gates passed. The whole API test gate is explicitly incomplete as a green
release signal because of the disclosed IPsec fixture failures. The parent
authorized proceeding with the bounded runner acceptance once the narrow
baseline reproduction establishes these failures are unrelated; no unrelated
IPsec repair, exclusion, schema workaround or broad rerun is authorized.

The narrow baseline reproduction ran only
`TestProviderCreateReadDelete` and
`TestProviderGuardsPreserveWireGuardNoopsAndCleanup`, race-enabled, against fresh
disposable databases from frozen `9b5d17d48fe2380c85488831de32ca210c13797f`.
Open (4.009 seconds) and enterprise (4.584 seconds) reproduced the exact two
messages: `create: IPsec connection unavailable` and missing
`cross_gateway_clients_enabled` (SQLSTATE42703). IPsec source, targeted queries
and migrations are unchanged between baseline and `400dba4`. The latter error
matches `settingsFixture` deliberately migrating only through 160 while the
organization query reads the column introduced at 166. The underlying cause
of the first message remains unclassified; no broader baseline pass is claimed.
Evidence: `<preserved-local-artifact>`,
`open-tests.log`, `enterprise-tests.log`, `run-results.json` and
`source-comparison.json`. Both baseline databases were removed.

Acceptance disposition: proceed only with the explicitly approved single-host,
single-Minimal sandbox acceptance. The two representative IPsec failures
predate this change; the affected runner/sandbox gates are green. The full API
gate remains failed and disclosed. Do not interpret this decision as a general
release, audit, deployment to other environments or feature rollout approval.
The existing historical reservation, user policies and Mac enrollment are
preserved. A read-only CP inspection succeeded through the existing deployment
SSH identity; the current Mac key is reserved for new runner/sandbox access.
Neither private key was read, copied or printed.


## Historical host attempt

The separately approved host attempt was blocked by regional capacity and supplied no native runner acceptance. That operational record remains preserved in its original source branch. It does not authorize provisioning or activation for this PR. Later qualification and final combined checks are reported in [the sanitized validation summary](S-sandbox-pr-validation.md).
