# NAT completion review — fixes approved

User disposition: **fix all four**, received 2026-09-09 after presentation of
the ranked findings and proposed configurable 6/device, 30/owner, 300/org
rolling-minute issuance defaults. Implement these defaults transactionally;
refusal must preserve the existing session and return a bounded retry response.
The historical HELD text below records review state before that approval.

2026-09-09. Two independent read-only finders examined the current server/node
and desktop/helper working trees. This is a bounded review, not complete beta
qualification. The historical findings below have now been folded to the extent
recorded in the implementation checkpoint below. Existing dirty work is preserved.

## Ranked release findings

1. **P1: forwarding authorization age.** In
   `apps/node/internal/relay/runtime.go`, ICE negotiation runs before packet
   pumps and a newly started 30-second lease. Negotiation can consume most of
   its own 30-second budget after the last authorized CP response. New forwarding
   can therefore start after authorization is already stale. Carry the deadline
   through negotiation and reauthorize before starting pumps; failed reads never
   grant fresh forwarding time. Test delayed negotiation plus CP loss.
2. **P1: gateway re-home retains the old carrier.** Client
   `apps/client/src/main/ipc.ts` still calls `tunnel.setGatewayPeer`; both helper
   backends perform ordinary peer swaps on the single-use relay bind. A different
   endpoint is rejected by the pinned bind; a new key at the same endpoint still
   uses the old gateway's negotiated carrier. Use the owner-fenced managed fresh
   session/reconnect path for relay re-home, and refuse incompatible in-place
   swaps before mutating peer state. Preserve ordinary direct re-home.
3. **P1: TURN issuance lacks an abuse bound.**
   `apps/api/internal/connectivity/store.go:Create` replaces the generation and
   issues new credentials without a transactional issuance throttle. Old TURN
   credentials remain valid until expiry; node worker/message limits do not
   bound a credential holder allocating directly at coturn. Disposition needs
   explicit per-device/owner/org limits and relay allocation/bandwidth caps.
4. **P2: IPC timeout contradicts negotiation budget.** Relay preparation and
   tunnel-up use the client's generic 15-second helper timeout while helper
   ICE gather/connect have a 30-second budget. Set an explicit bounded relay
   timeout covering that budget; keep ordinary IPC defaults unchanged. Test
   delayed success, timeout cleanup and cancelled ownership.

## Proposed disposition (not approved by this file)

Fix all four; use focused regression tests and the affected real-wire scenarios.
For issuance, propose initial configurable rolling-minute ceilings of 6/device,
30/owner and 300/org, atomically enforced without extending an old credential or
session when refused. These are proposed conservative product defaults, not an
industry standard or proven capacity specification. Define retry semantics and
coturn caps in the decision paper before implementation.

## Finite remaining delivery path

1. Disposition and close the findings above; no new UI polish or unrelated work.
2. Finish minimal customer relay packaging and truthful gateway capability/status.
3. Qualify only outstanding or affected transport/lifecycle cases, including
   native Windows and routing/MTU. Do not count cross-builds as Windows evidence.
4. Consolidate scoped product changes, run applicable final gates, review folded
   code, open coordinated draft PRs; obtain exact-head CI and fresh merge approval.

Existing live Mac relay/policy/renewal/outage evidence is retained with its stated
scope. General NAT direct hole-punching is not proved by a relay-only walk.
The current ICE agent gathers host/relay candidates, not a qualified
server-reflexive discovery path. Do not make that broader availability claim.

## Dependency discovery, not adoption

Upstream latest Docker release checked 2026-09-09: coturn `4.18.0-r0`, published
2026-09-08; index digest
`sha256:bbefd3e1fdfdc0d58770fe01b581fd8b00d9f3a5580d00acb77cf719a6bc78e3`.
This was registry inspection only: not deployed, pulled for execution or
qualified. Existing live proof used the previously recorded 4.17.2 pin.
Source: https://github.com/coturn/coturn/releases/tag/docker/4.18.0-r0

## Approved-fix implementation checkpoint — 2026-09-09

Changes remain in the server and separate client working trees; not deployed,
released, merged, or proven by exact-head CI. Do not inherit earlier live evidence
as a live test of these changed binaries.

- Forwarding authorization starts at the authoritative request's start time,
  remains bounded through ICE, and is rechecked before packet pumps start.
  Delayed/error reads cannot extend an expired lease.
- Relay re-home closes its single-use carrier and enters the existing owner-fenced,
  bounded reconnect path. Both helper backends refuse an in-place relay peer swap.
  Fresh Connect obtains the canonical current dial key/endpoint. CP session binding
  reuses the existing HA election, rather than the device's old assigned node.
- Migration 0141 adds a transactionally serialized issuance ledger. Defaults are
  6/device, 30/owner, 300/org per rolling minute. Refused replacement preserves the
  current generation. Same-side/session/minute mailbox reads reuse credentials;
  subsequent issuance minutes are counted as well as initial creation. HTTP 429
  tells the caller to wait at least 60 seconds. Relay allocation/bandwidth caps
  and customer packaging remain separate unfinished work; this is not a complete
  coturn abuse-control claim.
- Relay prepare/up use an explicit 35-second IPC timeout; ordinary operations
  retain 15 seconds. Actual 16-second delayed prepare and up tests pass.

Observed checks: generated Go/TS/sqlc completed; open PostgreSQL race regression
tests passed including HA promotion and preserved session on throttling; desktop
main-process suite 317 passed, followed by focused 403/409 heartbeat tests (2
passed) for the later HA change. Client typecheck/build and both API edition builds
plus scoped vet passed. Full helper race tests and Windows cross-build passed;
the cross-build is NOT a native Windows walk. A fresh isolated database migrated
through 141 with dirty=false. Full story gates and new live qualification remain.
Final enterprise race suites for connectivity, HTTP and nodes also passed, as did
the explicit same-minute credential stability/next-minute rotation regression.

### Re-review: one new P2 HELD for disposition

The new recoverable `ErrGatewayChanged` / HTTP 409 branch must first compare the
stored session's owner/org/device binding with current eligibility. Otherwise a
new owner presenting the prior owner's session identifier after simultaneous HA
promotion can receive 409 instead of terminal 403. No packet-access bypass was
demonstrated. Proposed narrow fold: check the immutable ownership binding before
the recoverable branch and add an ownership-change-plus-HA PostgreSQL regression.
Independent reviewer found no other issue in that bounded client/HA inspection.
This finding is not folded pending disposition under CLAUDE.md's review protocol.
