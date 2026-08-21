# F03 — Managed agent bootstrap and enrollment decisions

This is the F03 story-close paper. It records measured behavior and the
live-wire proof boundary. The exact implementation commit
`bb7a40621444f2e8569a07a0b73deda59aeb0811` passed the authorized AWS
development approval-on walk with its API, signed descriptor, runtime, unit,
and real reporter source- and digest-bound to that commit. Redacted evidence is
under `walk-artifacts/F03/20260815T091341Z/`. The boxwalk is **SATISFIES**;
story status remains a root-review and plan-ledger decision.

## Acceptance question

Can an operator issue a gateway-bound, one-time managed-agent bootstrap command
without the control plane ever storing or returning a server-generated private
key, and can that command establish a durable agent identity with a narrowly
scoped runtime credential?

## Decisions — LOCKED

### D1 — Bootstrap token is hash-only and one-time

The issue endpoint returns one random token once. PostgreSQL stores only its
SHA-256 hash, with a 32-byte database check, an expiry, and a consumed marker.
Redemption locks the token-derived advisory key and consumes it in the same
transaction as device and runtime-credential creation. Wrong, expired, and
consumed tokens have the same external refusal code.

Measured evidence:

- `TestManagedAgentBootstrapIsHashedSingleUseAndClientKeyed` passed against
  PostgreSQL 16 with the current shared chain through 0093.
- `TestManagedAgentBootstrapConcurrentRedemptionCreatesOneDevice` passed with
  exactly one success and one invalid-token refusal.
- `apps/api/db/migrations/0090_agent_bootstrap_tokens.up.sql` checks both hash
  columns at 32 bytes and binds token org to gateway org.

Rejected alternative: persist the plaintext token for support or replay
lookups. Rejected because database compromise and logs would become bearer
credential compromise; the keyed hash lookup is sufficient.

### D2 — The Linux host owns the WireGuard private key

The browser/API payload contains only the bootstrap token and the client-
generated public key. The bootstrap response contains a private-key placeholder,
not a private key. The installer generates the private key locally, validates
the response, writes temporary files, installs mode 0600 files, and only then
brings up the interface.

Rejected alternative: server-generate and return a WireGuard private key.
Rejected because it violates client key provenance and expands the API/browser
secret boundary.

### D3 — Runtime credential is a separate, narrow, one-time secret

Redemption returns one runtime credential exactly once. PostgreSQL stores only
its SHA-256 hash, binds it to the same organization and the created `agent`
device, and has no human/org policy permissions. It is reserved for the F04
configuration poll/report channel.

Rejected alternative: reuse the bootstrap token for ongoing runtime traffic.
Rejected because a one-time enrollment credential and a durable machine
credential have different lifetimes and revocation requirements.

### D3a — The managed runtime is the sole WireGuard interface owner

The managed bootstrap installer installs only the signed systemd runtime and
its root-owned `/etc/wireguard/runtime.conf`, runtime credential, and state.
It refuses an existing `runtime` interface before redemption. The runtime owns
apply, restart, and offboarding; the installer does not create a second
`tunnex` interface or duplicate config/credential files.

Rejected alternative: install `/etc/wireguard/tunnex.conf` and run `wg-quick`
from both the installer and runtime. Rejected because two owners can report a
successful install while the managed revision fails and revoke leaves the
installer-owned tunnel usable. The static connect command remains unchanged.

Ubuntu 26.04's enforced `wg-quick` AppArmor profile denies arbitrary config
paths, including `/etc/tunnex-agent/runtime.conf`. The runtime therefore owns
the standard, interface-specific `/etc/wireguard/runtime.conf`; this is not the
legacy static `/etc/wireguard/tunnex.conf` path and does not introduce a second
owner. The signed unit may write `/etc/wireguard` only for this runtime apply.

The same enforced profile transitions `wg-quick` into its `ip` and `wg` child
profiles. The live Ubuntu 26.04 proof showed that `NoNewPrivileges=true`
prevents those transitions before the retained `CAP_NET_ADMIN` can be used.
The managed runtime unit therefore sets `NoNewPrivileges=false`; it keeps the
root identity, narrow capability bounding and ambient sets, strict filesystem
protection, explicit write paths, and `/dev/net/tun` device allowlist. This
exception applies only to the managed runtime unit and does not change the
static connect command or control-plane gateway service.

WireGuard's `ip`/`wg` control path also requires a netlink socket. A matched
systemd live proof showed that restricting the unit to `AF_UNIX AF_INET
AF_INET6` makes `wg-quick` fail with `Address family not supported by
protocol`, while the same command succeeds outside that sandbox. The managed
runtime unit therefore adds only `AF_NETLINK` to `RestrictAddressFamilies`;
all capability, filesystem, device, identity, and restart limits remain
unchanged.

A terminal runtime-credential refusal is successful offboarding only after
the WireGuard disable completes. The managed entrypoint then exits with status
0 so `Restart=on-failure` leaves the service inactive; the unit remains enabled
and will recheck authorization cleanly on the next boot. A disable error stays
nonzero and retains systemd failure/retry visibility. The runtime is not given
permission to call `systemctl disable` or write `/etc/systemd/system`; explicit
uninstall cleanup owns disabling and removing the unit.

Device approval is distinct from revocation. A valid runtime credential bound
to a `pending` agent authenticates only far enough to receive a no-config wait;
the runtime stays fail-closed and polls with bounded backoff until approval.
Only `active` receives revision 1. Suspended, revoked, deleted, cross-org, and
unknown credentials remain the same uniform unauthorized terminal offboard.

### D4 — Database binding is authoritative

Composite foreign keys enforce `(org_id, gateway_node_id)` against the gateway
node and `(org_id, device_id)` against the device. A trigger rejects runtime
credentials for non-agent or deleted devices. These are database guarantees,
not only service-intent checks.

Rejected alternative: rely solely on handler predicates. Rejected because a
future writer, import, or direct SQL path could create a cross-organization or
human-device credential.

### D5 — Issuer attribution is preserved at redemption

The token issuer is copied into both `OwnerID` and `ActorID` before the common
device-create transaction. This was a proof-found correction: leaving
`ActorID` zero caused the required audit insert to fail the
`audit_logs.actor_user_id` foreign key. The correction preserves an attributable
system action without accepting an untrusted actor from the public request.

Rejected alternative: use a zero/system actor or accept an actor ID from the
public bootstrap request. The former breaks the audit FK and provenance; the
latter would allow caller-controlled attribution.

### D6 — Rollback is preservation-first

0090 down succeeds only when both credential tables are empty. If either table
contains rows, it raises and does not drop the tables or active credentials.
The isolated PostgreSQL proof observed refusal with rows preserved and both
hash lengths equal to 32 bytes. Current collision-safe evidence is committed at
`walk-artifacts/F03/20260815T081827Z/rollback-0090-current.txt`: empty down and
up-again passed, while non-empty down refused and preserved both bound rows and
32-byte hashes.

Rejected alternative: silently delete active bootstrap/runtime credentials on
down. Rejected because rollback must not turn a migration operation into an
irreversible credential revocation/data-loss operation.

## Mutation and absence review

The F03 mutations and their released call sites are:

| Mutation | Released call site | What the operator can do / cannot do |
|---|---|---|
| Issue bootstrap token | `apps/web/src/pages/Agents.tsx:120-138`, `POST /organizations/{orgId}/agents/bootstrap-token` | An authorized operator can issue a command for the selected gateway. There is no client-side roster reload because issuance has not created a device. No call site exposes token history, plaintext re-display, or token deletion. |
| Redeem bootstrap token | Generated command from `apps/web/src/lib/agentview.ts:321-326`, `POST /api/v1/agent/bootstrap` | The Linux host can redeem once with its public key. The browser cannot redeem on the host’s behalf and cannot supply a private key. There is no API/UI call site for replay, renewal, or runtime-credential re-display. |
| Revoke device | `apps/web/src/pages/Agents.tsx:141-157`, `POST /organizations/{orgId}/devices/{deviceId}/revoke` | The operator can revoke from the Agents confirmation flow. The API returns no body; the UI tells the operator the credential stops working. There is no separate F03 runtime-credential revoke control; the existing device revoke path is the offboarding authority. |
| Remove revoked device | `apps/web/src/pages/Agents.tsx:157-166`, `DELETE /organizations/{orgId}/devices/{deviceId}` | The UI only calls delete after successful revoke. A failed delete leaves the revoked row visible and tells the operator it was revoked but could not be removed. There is no raw active-device delete call site. |

### Post-mutation states

- Expired token: redemption is refused like any other invalid token. The
  currently released operator message is the generic command failure from
  `curl`/validation; the page does not automatically re-issue or fabricate a
  roster row. A fresh issue action is required. This is held for review below.
- Consumed token: replay is refused identically. The one-time modal is
  dismissed or copied once; the UI does not claim that a device exists merely
  because issuance succeeded.
- Revoked device: the UI says the existing tunnel credential will stop working,
  then requests roster removal. If removal fails, it explicitly says the agent
  was revoked but could not be removed.
- Removed device: the roster reload removes the row, while the revocation
  record/CRL remains authoritative. Re-enrollment requires a new bootstrap
  token and a new device identity.

### Held recovery decisions

#### H1 — Existing local install when bootstrap is retried (P1) — LOCKED

The current command writes fixed paths and its failure trap removes those paths.
That is a red safety invariant when a host already has a Tunnex config or agent
credential. Repository conventions measure two viable strategies: `scripts/mutate.sh`
backs up, restores, and verifies bytes; the desktop/device flows preserve local
state when a remote mutation fails. F03 has not chosen between:

- **H1-A — refuse-overwrite (LOCKED):** before changing anything, refuse if
  any managed runtime binary, unit, config, credential, or state target exists.
  The command reports a safe explicit existing-installation error and stops
  before key generation, token redemption, release download, file writes,
  service mutation, or cleanup of those managed targets. This has the smallest
  crash window and makes an accidental second enrollment non-destructive, at
  the cost of a manual replacement step.
- **H1-B — preserve-restore (REJECTED for F03):** snapshotting existing files
  and restoring exact bytes/modes on every failed path is smoother for deliberate
  replacement, but it creates a larger crash window and risks tearing down an
  unrelated existing interface. Deliberate replacement can be a separately
  reviewed operation.

Current evidence: the new web test named
`refuses existing managed targets before changing config or credential bytes` is
now a required acceptance invariant: the managed-target refusal must leave
existing bytes, modes, and service state unchanged. The separate WireGuard
config overwrite behavior remains outside this decision.

#### H2 — Expired or consumed bootstrap recovery (P2)

Measured one-time-secret patterns say the secret is shown once and a lost or
expired credential is recovered by minting a fresh credential, never by
re-displaying or extending the old one. Existing gateway/device recovery text
uses explicit re-enrollment or re-issue language, and the F03 API already
creates a new device identity on a new redemption. F03 therefore has two
surface options:

- **H2-A — explicit re-issue action (RECOMMENDED, HELD):** keep the current
  generic redemption refusal, but provide an operator-visible “Issue a new
  bootstrap command” action/copy after expiry or consumption. It must call the
  existing authenticated issue endpoint and never show the old token.
- **H2-B — no special recovery surface (HELD):** retain the current behavior;
  the operator returns to the enrollment form and issues again manually. This
  minimizes UI state but makes the recovery path less discoverable.

No option is folded. The current browser command cannot distinguish expiry from
other invalid-token refusals, by design, so any H2-A copy must not become a
token-validity oracle.

#### H3 — Signed runtime release inputs for the copied command (P1) — LOCKED / APPROVED

The released command formerly required `TUNNEX_RELEASE_TAG`,
`TUNNEX_RELEASE_SOURCE_SHA`, and `TUNNEX_RELEASE_PUBLIC_KEY` before it would
download or verify a runtime asset. The repository's authoritative release
path is the deployment-mounted signed descriptor at
`/var/lib/tunnex/release.json`, with the trust key and source SHA held in
deployment configuration. `releaseverify` emits the verified source SHA and
runtime asset/unit fields, but the public `/meta` contract exposes only upgrade
version/source-SHA facts; it does not expose an immutable release tag, the
descriptor URL/path, or the trusted public key. The released Agents UI passes
only the bootstrap token and API URL.

Therefore F03 must not invent a release tag from arbitrary version text, embed
a trust key in the browser command, or use `latest`/the mutable catalog as a
substitute. The canonical deployment rule is already measured in
`deploy/install.sh` and `deploy/get.sh`: a `v*` release uses that exact tag,
while a `sha-*` release uses `tunnex-build-${SOURCE_REF}`. The copied command
is self-contained only when an authoritative server-owned bootstrap package
metadata contract supplies the immutable tag, expected full source SHA, and
deployment-pinned public verifier key. The approved contract is the typed
metadata DTO below; the generated command passes this public verification
material directly to `releaseverify`.

##### H3 decision-ready contract proposal

The smallest safe server-owned seam is the existing authenticated issue
operation, `POST /api/v1/organizations/{orgId}/agents/bootstrap-token`, extended
so the `201` response is issued only after the server has loaded and verified
its mounted descriptor. The response must be exactly:

```yaml
bootstrap_token: string             # shown once; existing one-time secret
release:
  tag: string                       # immutable v* or tunnex-build-* tag
  source_sha: string                # full 40-hex commit SHA
  manifest_url: string              # immutable tag URL, never latest/catalog
  verifier_key_id: string            # identifier only, not a private key
  verifier_public_key: string        # deployment-pinned Ed25519 public key, base64url
  runtime:
    binary: tunnex-agent-runtime
    version: string
    linux_amd64: { name: string, sha256: 64-hex, source_sha: 40-hex }
    linux_arm64: { name: string, sha256: 64-hex, source_sha: 40-hex }
    unit: { name: tunnex-agent-runtime.service, sha256: 64-hex, source_sha: 40-hex }
```

`release` is derived only from `release.Load`/`VerifyManagedAgentRuntime` and
must satisfy all of these equalities before the token insert: every asset
`source_sha` equals `release.source_sha`; the descriptor source SHA equals the
configured `TUNNEX_RELEASE_MANIFEST_URL` source when that existing deployment
override is set; otherwise the tag is used with the measured canonical release
URL convention; and the runtime names/digests are copied from the verified
descriptor, not from browser configuration. Any configured URL must be HTTPS,
have no query/fragment, and end in the exact immutable `/<tag>/release.json`.
The response
contains no signing private key, bootstrap hash, runtime credential, WireGuard
private key, or raw descriptor signature. `verifier_public_key` is public
verification material, normalized as base64url, and is returned only in the
authenticated one-time enrollment response; `verifier_key_id` remains for
audit and diagnostics. The generated command therefore has no external
environment-variable trust-root prerequisite.

The operation ordering is:

1. Authenticate the session and resolve the organization permission
   (`org:update`), preserving permission-before-edition/no-oracle behavior.
2. Apply the existing Enterprise/license gate; open edition returns the same
   `403 edition_required` contract and performs no token mutation.
3. Validate the required request body shape.
4. Load and verify the server-mounted descriptor and runtime assets. Missing,
   malformed, unverifiable, source-mismatched, or incomplete metadata returns a
   generic `503 bootstrap_unavailable` with no path, key, tag, digest, or
   secret details and performs no token mutation.
5. Only after steps 1–4 pass, issue the hashed one-time token in the existing
   transaction and return the typed response. A database failure returns the
   existing safe mutation error; the plaintext token is never logged.

The UI consumes `release.manifest_url`, `release.tag`, and the selected
architecture's signed asset/unit fields from this response when constructing
the shell command. It never renders the verifier key, token hash, runtime
credential, private key, or full descriptor. The command still runs
`releaseverify` and checks the downloaded bytes, selected architecture, unit
name, unit digest, and source SHA before mutation; DTO fields are inputs to
those checks, not a replacement for signature verification.

##### H3 alternatives (only these two are viable)

| Option | Shape | Rejected/selected rationale |
|---|---|---|
| A — server-emitted pinned command | Extend the same `201` with `bootstrap_token` and a complete `install_command`, generated from the verified descriptor and deployment URL. | Smallest browser change, but moves shell quoting, platform branching, secret redaction, and installer behavior into the API handler. A command response necessarily carries the one-time token and is harder to lint/type-check as a security boundary. Rejected for F03; retain only if the release owner cannot expose the typed fields safely. |
| B — typed metadata DTO | Extend the same `201` with the typed `release` object above; the existing UI builder consumes it and remains the only shell generator. | **LOCKED / APPROVED.** Keeps release provenance server-owned and typed, reuses `release.Load`/`VerifyManagedAgentRuntime`, preserves the existing one-time token boundary, and makes asset/source/digest assertions independently testable. |

Migration and rollback are additive: no database migration is required; old
token rows and redemption remain unchanged. The server must verify release
metadata before inserting a new token, so a missing release descriptor cannot
leave an orphaned usable token. Deploy the API/configured trust-root
prerequisite first, then expose the DTO and update generated clients/UI in one
generation. Rollback removes the UI consumption and stops issuing the new
package response, while existing consumed/unused token rows remain valid under
the old redemption contract; no secret is re-displayed.

Acceptance gates for H3: OpenAPI/source contract and generated client drift
checks; authorized owner receives all fields while member, unauthenticated,
open-edition, and release-verification failures receive no metadata or
mutation; exact tag/source-SHA/name/digest equality tests against a signed
fixture; command DOM/response scans for secrets and trust material;
tamper/wrong-architecture/missing-descriptor refusal before token insertion;
and the real Linux/systemd boxwalk.

##### H3 reuse map and deployment prerequisite

- Existing issue handler: `apps/api/internal/http/agent_handlers.go:19-31`
  performs `authorize(..., rbac.PermOrgUpdate)` and calls
  `devices.IssueAgentBootstrapToken`; it is the ordering seam for the verified
  release preflight.
- Existing OpenAPI/schema/generated surfaces:
  `openapi/openapi.yaml:665-690,4553-4559`,
  `apps/api/internal/api/api.gen.go:603-606`, and
  `packages/shared/src/api.d.ts`'s generated operation/model entries. These
  must be changed through the normal OpenAPI generation once H3 is approved.
- Existing UI consumers:
  `apps/web/src/pages/Agents.tsx:416-438` receives the one-time response and
  `apps/web/src/lib/agentview.ts:324-344` generates the shell command. The
  latter should consume only the typed DTO and retain all local byte checks.
- Existing provenance helpers:
  `apps/api/internal/release/manifest.go:117-131` and
  `apps/api/cmd/releaseverify/main.go:20-58` already enforce descriptor and
  managed-runtime completeness; no second verifier should be introduced.
- Existing deployment inputs:
  `apps/api/internal/config/config.go:155-160` loads
  `TUNNEX_RELEASE_MANIFEST_PATH`, the optional immutable
  `TUNNEX_RELEASE_MANIFEST_URL`, `TUNNEX_RELEASE_PUBLIC_KEY`, and
  `TUNNEX_RELEASE_SOURCE_SHA`; `apps/api/cmd/server/main.go:357-360` loads the
  mounted signed descriptor. The server projects the same configured public
  verifier key in the authenticated one-time bootstrap response; no host-side
  environment variable is required.

## Current acceptance evidence

The real Ubuntu 26.04/systemd walks exercised the Enterprise/Scale development
control plane at schema 93. A uniquely enrolled current-head node agent sent
the real report and status channels; the released Agents payload showed the
managed peer online with a fresh handshake, and runtime status was connected
at desired/attempted/applied `1/1/1`. Restart re-established the handshake,
consumed-token replay returned HTTP 401 without mutation, and revoke removed
the interface and produced a clean status-0 inactive service with no restart
storm. The revoked credential then returned HTTP 401. Cleanup removed only the
disposable F03 resources and preserved host prerequisites and unrelated
control-plane state. The latest run additionally proved a pending agent stays
fail-closed in the same running process and applies revision 1 after owner
approval without a manual start. It does not close the story yet: the deployed
API predates concurrent current-source status changes, and its response omitted
the now-required `health` field. See `docs/F03-boxwalk.md` and the redacted
artifact path above.

The following are substitutes, not live-wire satisfaction:

- PostgreSQL 16 migration and enterprise service tests: PASS.
- `go test ./db -run TestAgentBootstrap -count=1`: PASS.
- `go test ./internal/http -run TestSessionlessRequestsAre401 -count=1`: PASS.
- `pnpm --filter @tunnex/web test -- test/agentview.test.ts`: 35/35 PASS.
- `pnpm --filter @tunnex/web typecheck`: PASS.

The live Linux-host walk procedure and completed result are specified in
`docs/F03-boxwalk.md`.

## Rejected scope

- No server-generated WireGuard private key.
- No plaintext bootstrap/runtime secret persistence or logging.
- No runtime credential with human, organization-policy, or general API
  permissions.
- No additional migration beyond reserved 0090 for bootstrap persistence;
  migration 0091 is owned by the adjacent runtime story.
- No automatic roster reload after token issuance.
