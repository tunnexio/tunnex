# WF-A — device re-homing on hub failover (client HA) — commit-one

**Origin:** EPIC 8 smooth walk (2026-07-23, `walk-artifacts/S8.6/SMOOTH-WALK-record.md`,
Test A). A split-tunnel device peers with ONE gateway (its assigned node, a static endpoint).
When that gateway's DATA PLANE dies, the client is stuck "Connecting…" and recovers ONLY when
ITS gateway returns — CONFIRMED on the wire (the mac reconnected the instant aws-gw-1 restarted,
NOT when aws-gw-2 was promoted). **Hub HA is site-transit redundancy, not device-connectivity
redundancy.** This is a FEATURE, not a hotfix — decision-first, held for founder ruling.

**Scope (founder-set, honest): v1 = re-home a connected device when its hub is PROMOTED-PAST
(the walk's exact scenario).** Roaming / latency-based / nearest-hub selection is explicitly
NOT this story.

## D-WFA-5 (NEW — surfaced at WF-A build-start; HALT, needs ruling BEFORE code) — the device→gateway model

The ruling says "the device's config re-compiles to the promoted HUB." But the mint-path trace
shows a device is NOT necessarily on the hub: the client picks `activeNodeId` = **the FIRST active
node** (`apps/client/src/main/httpdeviceapi.ts:46-52`; web: `nodes[0].id`,
`apps/web/src/pages/Devices.tsx:80`), and the CP bakes the config endpoint = **that node's**
Endpoint (`apps/api/internal/devices/service.go:264`, `node.Endpoint`). In the walk the first
active gateway HAPPENED to be the hub (aws-gw-1), so the two coincided — but they are not the same
thing. Before building, RULE the model:

- **(A) devices attach to the ACTIVE HUB by construction.** The mint-path picks the active primary
  hub (not "first active"); the config endpoint is DERIVED from the active hub; re-home = follow the
  hub's promotion. Cleanest re-home story (one moving target — the hub), but changes the mint-path
  node selection AND makes a device's gateway a derived value, not a stored node_id. Question: what
  about an org with NO hub set (single gateway, unpinned)? → the sole/elected gateway, degenerate-fine.
- **(B) devices keep their assigned node_id; re-home fires only when THAT node is a hub-set member
  that gets demoted.** Minimal change to the mint model; but a device on a NON-hub gateway (a future
  per-site local device) never re-homes — is that in scope? For v1 (the walk = a device on the hub)
  it covers the case, but leaves a "device on a spoke gateway" gap unaddressed (register it).
- **(C) hybrid:** keep node_id, but on promotion re-point the config endpoint to the promoted hub
  when the device's node was the demoted primary. The device's "home" stays its node_id for
  identity/peer-placement, but its DIAL endpoint follows the active hub.

**RULED (founder): (C) — identity STAYS (node_id), the dial endpoint DERIVES.** node_id conflates
two facts: WHICH gateway holds the device's peer/identity (assignment — stable; revocation + audit
reference it) and WHERE the client dials (endpoint — situational; must follow the active hub). (A)
collapses them → re-mints identity every promotion, churns the home for a transport concern, makes
device history unreadable across failovers. (B) keeps them conflated + inherits the spoke gap. (C)
SEPARATES them: keep node_id as identity/assignment, derive the dial endpoint from the active hub
set at config-compile time.

**Conditions (ruled):**
- **Endpoint from the ONE-truth chain:** the device config endpoint = `deriveActive`'s HEAD (the
  active primary) — the SAME value the compiler threads to the data-plane graph + policy compiler.
  Not a second election, not a snapshot. RED: promotion → the device's next compiled config carries
  the promoted hub's endpoint, by construction of the shared value.
- **Devices-on-spokes gap STAYS REGISTERED** (not silently closed): (C) fixes a device whose dial
  target is a FAILED HUB. A device whose assigned node is a non-hub SPOKE that dies is a different
  scenario (no promotion event fires) — the named deferral stands, with (C)'s derivation noted as
  the seam a future fix extends.
- **Identity-stable RED:** a device's node_id, audit history, and revocation semantics are
  UNCHANGED by a promotion — the proof (C) didn't smuggle (A).

### D-WFA-5b (peer-hosting verify — VERIFIED, the companion rides this story)

**VERIFIED (cited): (C) is a HALF-FIX without a companion.** `ListActivePeersForNode`
(`apps/api/db/queries/devices.sql:164`, `WHERE d.node_id = $1`) scopes a device's peer to its
ASSIGNED node only. So a device with node_id = the demoted primary, dialing the PROMOTED hub's
derived endpoint, hits a hub whose peer set does NOT include it → **the handshake fails, (C) alone
is a half-fix.** COMPLETION (rides this story, same fix's other half): **a device assigned to a
hub-set member is compiled onto EVERY hub-set member's DesiredState** — warm on standbys exactly as
site-links are warm (the standby HOLDS the device peer so the dial lands on a hub that already knows
the device; the device's /32 AllowedIPs rides the active-primary recompile on promotion, mirroring
the site-link single-valued invariant). Sub-item: standby device-peer AllowedIPs — empty-warm
(pubkey only, /32 added on promotion) vs full — decide at build per the site-link precedent (lean:
empty-warm, single-valued, the promotion recompile adds the /32). RED: a device assigned to a
hub-set member appears in the promoted hub's peer set (the dial's handshake completes post-promotion).

**BUILD STATUS (CP tier DONE):** slice 1a `widenedDevicePeers` (`e18d4df`, DB-red PASS: primary /32,
standby empty-warm — the empty-warm sub-item ruled at build per the lean) + slice 1b
`activeHubDialFrom` pure primitive (`0807f3a`, red pins primary/standby→active-primary,
spoke→not-derived, promotion-follows). CP foundation is one-truth + gate-able standalone.

### D-WFA-6 (RULED — (1) fold + reframe) — the dial-endpoint CHANNEL

**RULED (founder): (1) fold into routed-ranges + REFRAME the invariant** (the invariant was
MIS-STATED, not bent). Reframe, verbatim: *"The device's own identity — its private key, its pool
address, its enrollment — is minted once and NEVER re-fetched. The gateway it dials is not the
device's identity; it is a routing fact about the network, and WF-A makes it volatile by design
(the hub can change beneath a running device). Volatile routing facts ride the volatile channel."*
The S8.5 "no keys/endpoints" clause was written when the dial target was IMMUTABLE, so excluding it
cost nothing and looked like a security property. WF-A changes the world, not the principle: a
gateway's public key is not a secret and not the device's identity — it is the ADDRESS of a peer
the network says to talk to. The never-re-fetch invariant survives, correctly scoped: nothing the
device IS comes back over the wire; only what the network currently LOOKS LIKE.

**Condition 1 — field-level channel contract (in-spec):** the OpenAPI description states the
channel may carry NETWORK-TOPOLOGY facts (ranges, dial endpoint + gateway pubkey) and NEVER
device-identity material (no private key, no pool-address re-issue, no enrollment token) — so a
future field meets the RULE, not the precedent.

**Condition 2 — device_id authorization:** org auth stays (org:view); the handler ALSO verifies the
requested device belongs to the calling org (and, per the credential, the caller). The client
credential is the USER's session bearer (D-WFA-0 trace: `httpdeviceapi` uses the user bearer, not a
device cert) → the device must be OWNED by the authenticated user. MANDATORY cross-org/cross-device
RED (a device fetches ONLY its own dial) — the fixture the routed-ranges original cross-org red
established, extended to the device dimension.

### D-WFA-6-peer-swap (ACCEPTED) — the helper verb is a peer SWAP, not an endpoint update

Re-homing crosses to a DIFFERENT gateway → DIFFERENT pubkey → the verb is `set_gateway_peer`
(pubkey + endpoint: remove old, add new), same no-bounce dispatch class + kill-switch-untouched
probe as set_allowed_ips. **Condition A — atomic from the tunnel's view:** old-peer-remove +
new-peer-add in ONE uapi transaction where the substrate allows (a window with NO gateway peer is a
dead tunnel); if not atomic, order it ADD-then-REMOVE and say so. **Condition B — preserve the
device's own interface state:** address, private key, kill-switch arming UNTOUCHED — the red proves
the tunnel SURVIVES the swap + traffic resumes WITHOUT re-enrollment.

### D-WFA-6 (superseded banking note) — RULED direction: ride routed-ranges

The dial-endpoint the client polls to re-home is the THIRD volatile-operational client channel
(revocation → routed-ranges → dial-endpoint). **RULED (founder lean, strong): FOLD it into the
EXISTING routed-ranges channel — one poll, more fields — NOT a third poller.** The endpoint is
volatile-operational EXACTLY like routed-ranges (same auth class = revocation-poll, same fail-static
semantics, same cadence); three independent pollers = three cadences, three failure modes, three
fail-static implementations — the one-truth law applied to the client's control plane. Argue for a
separate channel ONLY if the shapes genuinely differ at build; otherwise the endpoint is a field on
the routed-ranges response (`sites.ListRoutedRanges`/the client `RoutedRangesMonitor`), derived
CP-side via `activeHubDialFrom`. NOTE: routed-ranges is ORG-scoped but the dial endpoint is
DEVICE-scoped (depends on the device's node_id + hub set) — verify at build whether the channel
carries device-scoped state cleanly, or the endpoint needs the device context threaded (it may make
the channel device-scoped, which is fine — the client polls for ITS device).

## D-WFA-0 (BLOCKING PREREQUISITE — decides the whole fork) — control-path independence

Does the device's CONTROL channel to the CP survive its DATA tunnel being down? If it rides the
WG tunnel (through the dead gateway), CP-driven re-homing is impossible — a device whose tunnel
is down can't be told to re-home.

**VERIFIED (2026-07-23, cited both ends) — the answer is CONDITIONAL on tunnel mode:**

**SPLIT-tunnel (the desktop DEFAULT — `index.ts:23` `DEFAULT_FULL_TUNNEL=false`; the walk's EXACT
scenario) → control path INDEPENDENT → CP-driven VIABLE.**
- Client transport: `HttpDeviceApi` uses the global (undici) `fetch`, NO wg0/utun binding, NO
  custom dispatcher/proxy — follows the OS routing table. All calls hit `${origin}/api/v1/...`
  where origin = the CP base URL (`cred.server`): `httpdeviceapi.ts:26-30,47,58,100,109,118,129,143`,
  bound at `ipc.ts:61,206,307,331`. Every monitor (Revocation/Approval/RoutedRanges/Health) rides
  this same CP origin, never a gateway.
- Helper routing: a split tunnel arms **NO kill-switch**; only the peer AllowedIPs (pool + org LAN
  ranges) route to utun; the cleartext physical default is left intact BY DESIGN
  (`backend_darwin.go:79-84`). The CP's PUBLIC IP is in neither the pool nor the org LAN ranges,
  so CP traffic egresses the physical interface and survives the gateway dying.
- **Empirically confirmed on the walk:** the app kept rendering live CP data (gateway states, hub
  set, sites) the whole time the tunnel read "Connecting…".

**FULL-tunnel → control path RIDES the tunnel → CP-driven FAILS (as-is).**
- The full-tunnel kill-switch does `block drop out all` with carve-outs ONLY for {loopback, tunnel
  iface, the WG ENDPOINT UDP, DHCP, NDP} — **NO exception for the CP** (`backend_darwin.go:301-323`,
  armed full-only `:85-89`). The CP's public IP is captured by the `0.0.0.0/1`+`128.0.0.0/1` tunnel
  half-routes (`wgcommon.go:123-139`) and/or dropped. Tunnel down → CP unreachable.
- The ONLY physical-gateway carve-out today is the WG endpoint host-route (`backend_darwin.go:126-150`)
  — **the CP could join it the same way** (see D-WFA-1's resolution).

**GATE RESULT:** D-WFA-1 is UNBLOCKED for split-tunnel (CP-driven confirmed). Full-tunnel gets a
clean resolution path (a CP-endpoint kill-switch carve-out), not a fork-flip.

## D-WFA-1 (RULED — CP-driven, locked) — the re-home MECHANISM

- **(a) CP-driven re-homing** — on promotion, the device's compiled config re-points its
  endpoint to the promoted hub; rides the EXISTING promotion→compile→push path (the same
  machinery hub-set failover already uses). ZERO client election logic (honors observe-never-
  vote, refused all epic). COST: requires the control path to survive gateway death (D-WFA-0);
  a device offline at promotion re-homes on its next CP contact (bounded lag).
- **(b) client-side multi-endpoint** — the device config carries the hub-set endpoints in
  priority order; the client tries them in order on handshake-death. Works during CP
  unreachability + needs no CP round-trip. COST: puts election-ADJACENT logic (which-hub-is-up)
  in the client — the exact class observe-never-vote refused; a client picking a hub the CP
  hasn't promoted diverges the two truths.
- **(c) both-layered** — CP-driven primary + client multi-endpoint fallback for CP-unreachable.

**FOUNDER LEAN:** (a) CP-driven as PRIMARY **IF D-WFA-0 confirms the control path is
independent** (cite it); (b) client-side multi-endpoint REGISTERED as the follow-up for
CP-unreachable scenarios. Ruling held.

**D-WFA-0 RESULT FOLDS IN (2026-07-23):** control path is independent for SPLIT-tunnel
(confirmed, cited) → **(a) CP-driven is viable for v1** (the walk's split-tunnel scenario).
Full-tunnel's control path rides the tunnel — but the fix is NOT a fork-flip to (b): it is a
**CP-endpoint kill-switch carve-out** — add the CP's IP to the full-tunnel pf pass rules exactly
as the WG endpoint host-route already is (`backend_darwin.go:126-150,301-323`), so a full-tunnel
device with a dead gateway can still reach the CP to be re-homed. This keeps CP-driven UNIFORM
across both modes and is a small, bounded helper change (a new decide-item **D-WFA-4** below).
(b) client-side multi-endpoint stays REGISTERED for genuinely-CP-unreachable cases (CP itself
down / network-partitioned), out of v1 scope.

**RULED (founder) — CP-driven re-homing, LOCKED.** On promotion, the device's config re-compiles
to the promoted hub (endpoint + the AllowedIPs the device already holds), rides the EXISTING
promotion→compile→push path, the client applies via the ordinary reconcile. Zero election logic
in the client; observe-never-vote preserved end to end. Conditions:
- **(a) promotion-triggered, NOT health-triggered.** The client NEVER decides its gateway is dead
  — the CP's failover controller (the ONE liveness truth) decides, and the device follows the
  SAME verdict the spokes follow. No client-side liveness opinion enters.
- **(b) the re-home is AUDITED on the same generation machinery** as everything else — a device
  silently hopping gateways is the two-truths class; the audit row IS the truth.
- **(c) fail-back re-homes the device home the SAME way** — one mechanism, both directions (the
  device-tier echo of the D4 hysteresis; failback promotion re-compiles the device onto the
  restored primary).

## D-WFA-4 (RULED — IN for v1) — full-tunnel CP-endpoint carve-out

Full-tunnel's kill-switch blocks the control channel (D-WFA-0). For CP-driven re-homing to work
in full-tunnel, the kill-switch must permit egress to the CP endpoint.

**RULED (founder) — IN for v1.** Shipping split-only would give the MOST security-conscious
configuration (kill-switch on) the WORST HA — backwards; the full-tunnel outage is exactly the
one a kill-switch user bought the product for. Terms:
- ONE CP-endpoint pass rule, mirroring the existing WG-endpoint host-route pattern
  (`backend_darwin.go:126-150,301-323` — precedent cited, mechanism proven), scoped to the CP's
  IP/port EXACTLY.
- **Threat argument (one line, founder-framed):** the CP is already the TLS trust root the device
  authenticates to — a pass rule to it widens NOTHING; the client still authenticates everything
  it receives. Not a broad exception; a single named carve-out.

## D-WFA-2 (RULED direction) — re-home rides the generation/audit machinery

A device silently hopping gateways is the two-truths class. The re-home MUST carry a
generation bump + an audit event (`device.rehomed` or rides `hub_set.promotion`'s consequence),
same as every other state transition this epic. No silent endpoint swap.

## D-WFA-3 — failback symmetry

When the original hub recovers and reclaims PRIMARY (M=5 fresh), does the re-homed device
return to it, or stay on the standby-now-primary? v1 default: follow the active primary (the
device tracks the hub set's members[0]), same rule as the site-link graph — consistent, no
device-special path. State explicitly.

## Reds (RULED — the acceptance set)

1. **ACCEPTANCE (the walk's EXACT fixture, CLOCKED):** connected device on the primary → gateway
   killed → promotion → the device's config re-homes within ONE push cycle → tunnel re-establishes
   to the promoted hub → traffic resumes — WITHOUT a manual reconnect. Stopwatch the re-home; this
   timeline joins the 4m48s failover as the demo's SECOND number.
2. **Run RED 1 in BOTH modes** — split AND full re-home IDENTICALLY (the D-WFA-4 carve-out makes
   full-tunnel reach the CP; the re-home path is otherwise one mechanism).
3. **Promotion-triggered, not health-triggered (D-WFA-1a):** the client emits NO liveness verdict;
   the re-home fires only from the CP controller's promotion. A test that flaps a gateway's
   data-plane WITHOUT a promotion must NOT re-home the device.
4. **Generation/audit (D-WFA-1b/D-WFA-2):** the re-home emits its audit event on the same
   generation machinery; no silent hop.
5. **Fail-back (D-WFA-1c/D-WFA-3):** original hub reclaims (M=5 fresh) → device re-homes back the
   same way; one mechanism both directions.
6. **Kill-switch invariant (D-WFA-4):** full-tunnel + kill-switch armed → CP reachable (carve-out
   live) AND everything else still dropped — the block-all invariant re-verified MINUS exactly one
   new named exception (the kill-switch's own reds re-run with the carve-out present).

**Sequence:** this paper (RULED) → build as its OWN story (compiler device-config path + client
reconcile + helper CP-endpoint carve-out) → targeted review on the peer-model + kill-switch
surfaces (both most-reviewed classes, UNDISCOUNTED) → box-walk: the walk's exact fixture, BOTH
tunnel modes, stopwatch on the re-home. NOT a hotfix — a story.

## D-WFA-4 — SLICE 3 BUILD RECORD (the carve-out landed; darwin)

Built on `story/S8.6-hub-ha` after slices 2a/2b. The ruled outcome ("full re-home identically")
required THREE mechanical pieces, all reusing the cited precedent — none a new mechanism, none a
new decide-item:

1. **CP-endpoint carve-out (the ruled "one named pass rule").** Full-tunnel Up now permits egress
   to the CP endpoint EXACTLY (`pass out proto tcp to <cp-ip> port <cp-port>`) + pins a host-route
   for the CP IP via the physical gateway — the identical mechanism as the WG-endpoint host-route
   (`buildPFRules` + the step-3a endpoint pin). Effect: the control channel becomes tunnel-
   INDEPENDENT in full-tunnel, matching split-tunnel's D-WFA-0 independence — which is *why* the
   dial tier can drive full-tunnel: the poll reaches the CP whether the tunnel is alive or dead.
   Threat argument (as ruled): the CP is already the TLS trust root; a direct pass to it widens
   NOTHING, and the client still authenticates everything it receives.
2. **WG-endpoint re-point on the swap (required for the swap to land).** A re-home moves to a
   DIFFERENT gateway box (new IP). pf permits by ENDPOINT IP, so the peer swap alone would leave the
   new gateway's handshake `block drop`'d and route-looped. So full-tunnel `SetGatewayPeer` now
   re-arms pf with the new WG endpoint (re-emitting the CP pass) + re-pins the WG host-route — the
   SAME Up mechanism, applied to the new gateway. Not a new surface: re-pointing an already-permitted
   class from hub A to hub B, strictly the identical trust posture.
3. **dialEnabled flipped on for full-tunnel + the refusal seam retired.** `UpdateGatewayPeer` no
   longer blanket-refuses full-tunnel; the BACKEND owns the policy. On darwin the full-tunnel re-home
   works when the CP carve-out is present. `rehome_full_tunnel_unsupported` is now reachable ONLY
   when the carve-out is ABSENT — i.e. the darwin backend received a full-tunnel Up with no
   `control_plane_endpoint` (a defensive refusal, never the normal path), OR the Windows backend
   (below). The refusal is retired on the working path, retained as the honest failure seam.

**Config plumbing:** `TunnelConfig.control_plane_endpoint` (optional, additive at ProtocolVersion 1).
The client derives it from the tenant API origin (host:port, 443 default) and sends it on full-tunnel
Up; the darwin backend carves it. Single-IP-CP assumption (the CP host resolves to one pinned IP,
exactly like the WG endpoint) — a multi-IP/rotating CP is a REGISTERED follow-up, not v1.

**PLATFORM PARITY — darwin lands, Windows DEFERS (named trigger + honest consequence).** macOS pf
permits by endpoint IP, so the carve-out is a `pass out` rule + host-route (landed, wire-provable on
the macOS walk box). Windows WFP permits by PROCESS (`permitWireGuardService`) — the WG endpoint
needs no per-IP permit (the helper process egress covers any gateway), BUT the CLIENT's CP TLS is the
Electron main process, which WFP's block-all drops in full-tunnel. A Windows CP carve-out is a NEW
WFP permit filter (remote CP IP+port) + a winipcfg host-route on the pinned wireguard-windows fork —
a change-averse surface (upstream-sync obligation) that CANNOT be wire-proven this session (the walk
box is macOS). **DEFERRED to S8.6b-win-carveout; TRIGGER = the first Windows full-tunnel HA walk (or
public-beta Windows readiness), whichever comes first. HONEST CONSEQUENCE until then: on Windows,
full-tunnel re-home is UNSUPPORTED — the windows backend refuses `SetGatewayPeer` for full-tunnel
(`rehome_full_tunnel_unsupported`), the client's dial tier fail-STATICs (keeps the current peer), and
a Windows full-tunnel device stranded on a dead hub needs a manual reconnect. Windows SPLIT-tunnel
re-home is UNAFFECTED (no kill-switch, control path already independent) and works identically.**
