# NAT product candidate — live AWS checkpoint

2026-09-09. User authorized deployment and testing, requesting continuation until
the customer test or a genuinely human-required blocker. Native application traffic
has now passed through the candidate, as detailed below. This is NOT a completed
GUI enrollment walk, signed release, final CI result, or merge-ready claim.

## Deployed

Account 735391218823, ap-south-1, identity checked before mutation.
Existing CP i-0679744e281749144: https://cp.13.126.184.110.sslip.io.
Dedicated gateway/relay host i-0d320abd28be9eaa9: 13.235.24.2.

- Existing Neon-backed CP schema upgraded 136 → 140, dirty=false. Candidate
  API/web images installed in the existing named Neon Compose project; previous
  images and `.env.before-nat-product-20260909a` retained for rollback.
- CP HTTPS and /healthz pass after deployment.
- New gateway container `nat-product-gateway-20260909a` uses the existing node
  identity/state, new binary, updated public CP URL, and private mTLS endpoint.
  Expired certificate recovered automatically by proof of possession; same node
  identity retained. Normal agent readiness passed. No manual WG peer/policy fix.
- Caddy obtained a trusted certificate for `relay.13.235.24.2.sslip.io`.
  TLS verification on TCP5349 passes without bypassing certificate checks.
- Organization relay profile enabled via API, revision 1; scoped credentials
  minted through ordinary authorized sessions. Shared secret is sealed by CP.
- Existing service 10.250.0.2:8080 restarted. Separate service at
  10.250.0.3:8080 created for negative control. Org policy enforcing, first grant
  enabled, second disabled. Actual gateway nft readback has first allow rule and
  default-drop. Application traffic evidence is recorded in the continuation below.

## Real wire result

Opt-in helper test `TestProductCPRelayNegotiation` uses the real CP login, owned
device session, CP-issued TURN credentials, gateway certificate-authenticated
signaling, and production Pion wrapper. Final run PASS in 15.00 seconds, selected
relay with no direct WireGuard UDP ingress open. Test closes its CP session.

Initial run failed waiting for gateway offer: the gateway's public self-access
to its relay was not admitted by SG-reference-only rules. Added exact host public
/32 self-access on TCP5349 and relay allocation UDP range, then the fresh run
passed. No product signaling bypass, SCP source patch, or manual payload exchange.

This proves TLS relay nomination/signaling, NOT native WireGuard application
traffic or normal GUI Connect. The latter requires installing the built Mac
helper; native admin authentication was unavailable noninteractively. Installed
helper was confirmed idle. A hash-pinned, backup-preserving install script is
prepared outside Git; user was asked to run it. A fresh-profile dev client was
launched. No privileged helper replacement has occurred at this checkpoint.

## Provenance

Uncommitted product changes over server branch base `ea14ac2`; client edits are
on `codex/nat0-desktop-proof`. Artifact hashes, not a fictitious committed SHA,
identify the deployed candidate. API/migration/node local and remote hashes match.

| Artifact | SHA256 |
| --- | --- |
| API enterprise | fa4c615533f7d1bf5fcb359fb5a075fd381735022e3fc9e6a1f59a70e455284d |
| Migration | e5f5676f04fa6a46795f2437f9d4a66659c46dd662f24197165bcfce98a9a96f |
| Linux node | 659ca9a9bdbbadc2ce3ac093b11f9f8eaf8fbf17bd9bc5e293a48df38ee07c51 |
| Mac helper, pre-install / pre-ad-hoc-signing artifact | 7a5a2a1b8deaba358038228c4703248e8c04c5bc4a9c43646fa35b4cf4c28288 |

## Retained infrastructure / next step

CP and dedicated NAT host remain running for the user test; old DB stays stopped.
No resources or existing data deleted. New certificate volume retained.
New ingress rule IDs, retained for ongoing testing:

- SSH laptop /32: sgr-015be748cc6029b4a (CP), sgr-04eca45a65d9cfc20 (NAT).
- Gateway-to-CP mTLS: sgr-00f38d403634e8d7d.
- ACME HTTP80: sgr-03ec555d4500b32d0.
- TLS5349 laptop /32 + gateway SG: sgr-0a06f48b914c8d04b, sgr-0b3b3bf5a2c7a83f0.
- Relay UDP49160–49200 gateway SG: sgr-076d135ae03f4b7d2.
- Relay self-public-/32 TLS/UDP: sgr-06033ae08bda7b611, sgr-0bfcecea32090a242.

After native helper authentication: test normal client Connect, authorized HTTP,
and denied service with live positive controls. Then qualify teardown/renewal
and report exact evidence. Ten-minute session rollover, Windows/full-tunnel,
full gates and independent review are not complete.

## Continuation: installed native helper and application traffic PASS

The preceding installation-pending paragraphs describe the earlier checkpoint.
The user subsequently installed and ad-hoc signed the candidate helper, retaining
the original binary. No additional privileged installation was needed.

The live driver invoked the built production `TunnelController` through the
trusted Electron executable, using the actual installed helper IPC connection.
It authenticated to the real CP, checked existing device ownership and gateway
WireGuard key, obtained a scoped session, and used normal CP signaling. This was
not a GUI-click or fresh-device-enrollment test.

- Added approved `10.250.0.0/24` through the ordinary CP routed-LAN API. The driver
  merged CP-approved ranges as the client monitor does; no manual local route repair.
- Actual native tunnel reported up. Both `10.250.0.2:8080` and `10.250.0.3:8080`
  passed HTTP positive controls with their grants enabled.
- Disabled only the second grant through CP, without reconnecting the tunnel.
  First service remained reachable; second service was denied. Helper AllowedIPs
  remained exactly `10.99.0.0/24, 10.250.0.0/24` throughout policy withdrawal.
- Driver completed successfully, brought the native tunnel down, and revoked its
  temporary bearer. Final helper status is down; default route remains `en0`.
  CP `/healthz` separately returned status `ok`.

For this run the dedicated NAT host's unrestricted outbound rule
`sgr-009adde465598934f` was replaced by TCP-only internet access
(`sgr-0370cdbc2bea4e499`), UDP DNS (`sgr-04c2c39bb8472d617`), and UDP49160–49200
to its own public /32 only (`sgr-058449eb2a9de96b7`). General outbound UDP was
absent on readback. These restrictions remain for the user's relay test.

TURN container `nat-product-turn-20260909b` runs the same configuration with
verbose logging; the previous `nat-product-turn-20260909a` is stopped and retained.
Live TURN usage records contain nonzero packet/byte counters (usernames omitted):
`rp=26 rb=3552 sp=16 sb=1364`, `rp=7 rb=784 sp=17 sb=1960`,
`rp=129 rb=14512 sp=98 sb=10768`, and `rp=111 rb=12444 sp=117 sb=12156`.
These are observed TURN counters, not inferred from profile configuration.

Diagnostic limitation: the gateway logs its local path as `direct` in this
relay-backed run. A one-sided relay/peer-reflexive pair is the suspected cause;
that local label is not authoritative end-to-end relay evidence. The earlier
client-side negotiation probe selected relay, and native-run TURN traffic and
network constraints provide separate evidence. Path-label qualification remains.

The fresh dev client's **Tunnex — Setup** window is ready for the user to enter
the current CP URL, sign in, and connect in split-tunnel mode. Expected result:
HTTP to `.2:8080` allowed; `.3:8080` denied. GUI enrollment/Connect remains unproven
until performed. Automatic renewal beyond the ten-minute session, Windows and
full-tunnel relay, full final gates, independent review, and exact-SHA CI remain
outside this successful native traffic claim. Product edits remain uncommitted;
this evidence commit does not identify them as a released build.

## GUI failure follow-up: lock contention and timeout classification

The initial GUI run did not sustain traffic. The gateway republished its offer
within the same session (observed gateway sequence 9, device sequence 1), while
the client kept the original ICE carrier and a surviving interface reported Up.
CP requests took multiple seconds, including a measured 13.8-second policy update.
The reused Neon DB is in US-East-2; CP is in ap-south-1. Geography alone does not
prove the failure cause. No database migration or pool-limit change was made.

Code inspection identified exclusive eligibility-device and session locks on
every heartbeat read, redundant concurrent reads from gateway polling, and all
gateway session errors incorrectly mapped to HTTP403. Candidate correction:
read-only operations take shared locks (writes retain exclusive serialization),
the transaction's bounded context reaches its callback queries, and transient
storage failures return 503 rather than an authoritative denial. Authorization,
posture/membership checks, and the 30-second lease remain enforced.

Real isolated PostgreSQL tests passed in both editions: shared readers coexist,
writes remain blocked by shared eligibility locks, replay remains serialized,
and key/posture/device denial checks pass. Error mapping tests also passed.

Deployed API artifact SHA256:
`02cd612c8a76848f2fdd7e3ad4f8a7c5e877d26b4b4f933c6aa305c784d9fb75`.
Image `tunnex-nat-product-api:20260909-lockfix`, built image `55acb5c234f9`.
Compose project is unchanged. Deployment adds
`/home/ubuntu/nat-product-20260909a/compose-lockfix.yaml` after the existing
`tunnex.yml`; future restarts must include that override to retain this image.
Original image and `.env` are retained. HTTPS health passed after replacement.

Client changes reject replacement established offers, preserve Failed over a
surviving helper Up, and queue at most one owner-fenced managed reconnect.
The GUI now requires a fresh handshake before displaying Connected. A fresh
authorization renews the preparation lease before negotiation. A subsequent
local-only refinement permits transient CP retry inside the existing lease;
it does not renew the helper lease on error and was not loaded by the ongoing
native driver below. Do not label that driver as exact-final-client acceptance.

Live driver against the deployed lock fix passed both positive service controls
and same-tunnel policy withdrawal: `.2:8080` reachable, `.3:8080` denied. During
the sustained run a separate read observed RX23756/TX24036 bytes and a successful
HTTP `native-pion-proof` response. Final duration/cleanup is recorded separately
when the driver exits. Automatic GUI recovery and ten-minute rollover are not
claimed by this driver; full web gates still include two stale split-repository
fixtures referencing missing server OpenAPI/design files.

The driver subsequently exited 0 after its full 120-second sustained HTTP loop.
Cleanup disabled the second grant, brought the tunnel down, and revoked the exact
temporary driver credential. This is a successful native sustained traffic and
same-tunnel policy walk, not a forced-recovery or final release qualification.

## Native automatic session rollover PASS

## Follow-up: measured Relay status and real TURN restart recovery

2026-09-09: user installed the new helper with rollback retained. Installed,
ad-hoc-signed SHA256 is
`9c7c39ea8340438e2c7880d051b15a78694de55c9dbe1e2e090409b61f6f2345`.
Signature verified, bundled helper synchronized byte-for-byte. The first attempt
refused `already_up` because the old GUI survived SIGTERM; that exact dev process
was stopped after confirming helper Down. No result is counted from that attempt.

Account 735391218823 and instance i-0d320abd28be9eaa9/public13.235.24.2 verified.
Only dedicated container `nat-product-turn-20260909b` was restarted for each
interruption. No CP/DB/policy/security-group modifications or resource deletions.

Initial isolated outage attempt failed. CP request logs show session GET HTTP500
at `2026-09-09T08:03:40.205913761Z`; the client transient classifier omitted 500
while accepting 502/503/504. A subsequent pre-correction run recovered generation
13→14, but did not erase the failed attempt. Correction includes HTTP500 in the
existing-lease bounded retry/recovery classification; it does not renew a helper
lease on error or treat 401/403 as recoverable. Focused mocked 500/403 tests pass.

Corrected-build live outage leg PASS: generation15 (expiry
`2026-09-09T08:20:00.55741Z`) reached HTTP with helper path `relay`. Actual TURN
restart broke the carrier. Changed-offer detection triggered one automatic fresh
generation16 (expiry `2026-09-09T08:21:41.032834Z`), again path `relay`, with
successful native HTTP. Exit0; helper down and temporary bearer revoked.
No forced HTTP500 injection occurred in this final cloud run; its deterministic
retry proof is the focused local regression, not an invented cloud assertion.

Loaded controller SHA256:
`ef27fd92002a5d8473004e0a31747f217822503aa4c8f69780d8232191a36b5b`.
Full client309/309 tests PASS. Renderer66/66 focused tests and build, helper race
suite/path classification, vet and macOS Intel build pass from the preceding
path-status slice. Product changes remain uncommitted/unreleased. Native driver
uses the production controller/owner queue but is not full Electron IPC/GUI proof.
This is bounded recovery with interruption, not seamless handover or full-network
qualification. Broader platform, outage/denial matrix, review and CI remain owed.

2026-09-09 follow-up: account 735391218823 verified again. CP, gateway, relay,
database expiry and policy configuration were unchanged for this leg. The dev
GUI was stopped while its helper was already down, preventing competing owners.

A private driver used the built production `TunnelController` and
`ManagedLifecycleCoordinator.serialForLease`, the installed Mac helper and actual
CP authorization. It re-proved owner/device/gateway/ranges before reconnecting.
No time acceleration, database lifetime edits or manual reconnect was used.

- Initial CP generation 9 expired at `2026-09-09T07:28:00.286677Z`.
- Authorized heartbeat triggered early renewal in the final 60 seconds.
- Old carrier closed; fresh CP generation 10 expired at
  `2026-09-09T07:37:33.335939Z`. Native authorized HTTP passed on connection 2.
- Driver continued beyond the ORIGINAL expiry plus 20 seconds, exited 0 and
  reported successful native HTTP. At least 108 periodic HTTP samples passed.
  Samples deliberately pause during break-before-make; this is not zero-loss
  or seamless handover evidence and interruption duration was not measured.
- Independent probes during connection 1: `.2:8080` HTTP200 with expected body,
  `.3:8080` timeout. Earlier both-service positive controls remain separate proof.
- Cleanup brought the native tunnel down and revoked only its temporary bearer.

Loaded client artifact SHA256:

| Artifact | SHA256 |
| --- | --- |
| dist/main/tunnel.js | 3c1bba49e841296bb1b8ff3f5c23f9e4772c5a806c9dbcd6747fae98c5792974 |
| dist/main/managedlifecycle.js | 5853a418a8bf27a2fe8a26f0c985ac02233108adfeb1b3a74b27ff4f606b2e00 |

Client source remains uncommitted over decision commit `450ad83`; no released
build or exact-SHA CI is implied. The driver reuses the production queue and
controller but supplies its own orchestration, not Electron's complete IPC or
GUI enrollment path. GUI automatic rollover is still a distinct qualification.

Additional local results: client 307/307 tests, typecheck/build; helper race/vet,
NAT-tagged suite, Windows amd64/macOS amd64 compile; renderer build; four dev-plist
tests; and server-lane full Linux `make test-node` PASS. Cross-compilation does not
prove Windows runtime relay support. Full final gates/review and broader NAT
failure/platform qualification remain required; no merge/release performed.
