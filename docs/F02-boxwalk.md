# F02 boxwalk — two agents on one gateway

## Status and proof boundary

This is the completed live-wire record for F02. H1-H3 are locked in `docs/F02-decisions.md`; the released-route quota, concurrency, lifecycle, permission, cleanup, and rollback legs below **SATISFY** the story acceptance. Unit and database tests are supporting evidence, not replacements for the released-route walk.

The walk must use the current story content tip and a real gateway plus two independently running agent hosts/clients. Do not hand-insert device rows to satisfy an enrollment leg. Record evidence during the walk under `walk-artifacts/`; scratch configs and private keys must be gitignored at creation and never committed.

## Invariants

For two agents A and B in one organization and homed to the same gateway/node:

- both enroll successfully, including a concurrent enrollment attempt;
- A and B have different device IDs, public keys, and assigned organization IPs;
- exhausting the available pool refuses the next enrollment without overwriting either existing identity;
- revoking/removing A leaves B active and usable with its original identity and address;
- 0089 down succeeds with at most one live agent and restores its constraint without data loss;
- 0089 down refuses with more than one live agent and preserves all rows and identities.

## Preconditions and provenance

1. Capture commit/content tip, API and gateway build identifiers, PostgreSQL migration version, edition/license state, organization ID, gateway/node ID, and pool configuration.
2. Confirm 0089 is up and the one-agent-per-node index is absent; confirm the public-key and organization-IP uniqueness constraints remain present.
3. Prepare an organization pool with exactly the smallest supported number of allocatable addresses needed for A and B plus the documented exhaustion attempt. Do not invent a CIDR or count: record the allocator’s measured usable capacity and the reservation rule.
4. Create two independent agent-host workspaces. Keep private keys, bootstrap tokens, and rendered configs outside the repository or under an ignored walk-artifacts path.
5. Verify no pre-existing live agent on the selected node will confound the count. Use read-only API/UI observation for staging; no direct database writes.

### Recorded run

- Edge: `http://127.0.0.1:18086`; `/api/v1/meta` reported `edition=enterprise`.
- One organization and one real gateway/node were used; migration version was `83`, clean.
- The owner cookie jar was scoped to a 0600 path and all recorded artifacts were redacted. No license, token, runtime credential, private key, or cookie value is included.
- Final cleanup restored quota to `NULL` and device approval to `off`; the disposable stack lease remained held for independent review.

## Walk legs

### 1. Baseline enrollment

Enroll A through the real operator/API flow and start its runtime. Record the bootstrap response, device ID, public key, assigned IPv4 (and IPv6 if enabled), gateway/node, handshake/readiness, and the Agents page row. Redact tokens and private keys.

**Result: SATISFIES.** A real diagnostic enrollment first exposed the concrete `node_not_ready` prerequisite; after the real gateway endpoint/key were available, enrollment returned `200`. The diagnostic identity was revoked and removed through the canonical API before the quota leg.

### 2. Concurrent same-gateway enrollment

From two operator sessions or two authorized enrollment clients, issue B and a second controlled enrollment concurrently, both targeting the same gateway. Use a barrier at the API request, not a database insert. Record both responses and the final agent list. Assert committed rows have unique IDs, public keys, and organization IPs and the same node ID; assert neither request reports a false success for a duplicate identity. Start both runtimes and record independent readiness/handshakes.

**Result: SATISFIES.** Three concurrent real bootstrap requests on the same gateway produced exactly **2 HTTP 200** committed identities and **1 HTTP 409 `agent_quota_exceeded`**. The two committed identities had distinct device IDs, public keys, and organization IPs.

### 3. Pool exhaustion boundary

Set the organization quota to the measured boundary, enroll A and B concurrently, then attempt the next enrollment. Capture the HTTP 409 `agent_quota_exceeded` body and the Agents page/operator message. Re-read the existing rows and addresses. The attempt must fail without changing A or B, without reassigning either address, and without a client-side remaining-count claim. Clear the quota (`null`) and repeat only if needed to prove the unlimited compatibility path.

**Result: SATISFIES.** Quota `2` was saved and returned by organization refetch. The third enrollment refused with the stable conflict and did not alter the two committed identities. Quota `NULL` was then saved/refetched and a subsequent enrollment returned `200`.

### 4. Revoke one, preserve the other

Use the Agents UI’s “Revoke and remove” flow for A, or its exact API equivalent if the UI cannot be used, and capture both responses. Confirm A’s credential/peer is no longer usable, A’s row follows the existing revoke/remove contract, and B remains active, listed, handshaking, and able to pass the same minimal health/traffic check with the original ID, public key, and IP. Capture the UI’s success or partial-failure feedback.

**Result: SATISFIES.** One agent was revoked/removed; the other remained active with its original identity. The released UI/API permission matrix proved owner `200`, member `403 forbidden`, unverified admin `403 email_not_verified`, and unauthenticated `401 unauthenticated`. Focused released-route UI absence/wiring tests passed **19/19**.

### 5. Rollback with at most one live agent

In an isolated disposable database at the 0089 state, arrange at most one live same-node agent using normal migrations/fixtures, snapshot its row and identity, and run 0089 down. Assert down succeeds, the one-agent constraint is restored, and the row and identity are unchanged. Record the migration version and re-apply 0089 before any subsequent leg.

**Result: SATISFIES.** The non-skipped Docker-network PostgreSQL 16 run succeeded. 0089 down restored the one-agent constraint and preserved the sole agent row and identity.

### 6. Rollback refusal with more than one live agent

In a second isolated disposable database at the 0089 state, arrange two live same-node agents and snapshot both rows, keys, addresses, and constraint state. Run 0089 down. Assert it refuses before data loss: both rows and all identities remain, the one-agent constraint remains absent, and the migration runner’s dirty/failed-down metadata is recorded exactly. Do not “repair” the database by deleting a row; stop and escalate the metadata handling as a held operational finding.

**Result: SATISFIES.** The historical then-numbered 0080 proof recorded version
`79`, dirty `true`. After collision-safe renumbering, the non-skipped
`TestMultiAgentPerGatewayRollback` passed on `tunnex-cp` against disposable
databases: 0089 down preserved the single-agent case, refused the two-agent case
without row or identity loss, and recorded the expected version `88`, dirty
`true`. Evidence: `walk-artifacts/F02/20260815T045504Z/migration-collision-proof.md`.

## Evidence packet and stop conditions

For each leg, retain timestamped redacted API responses, UI/DOM assertions, row/identity/address snapshots, gateway/runtime health, and command output. A failed leg stops the walk; do not reinterpret it as quota behavior or manually repair it. The recorded live legs are marked `SATISFIES`; focused unit/PostgreSQL checks are supporting evidence.

The walk is complete for the selected disposable stack. Findings and any new decision fork go back to `docs/F02-decisions.md`; this runbook does not reopen the locked source, lifecycle counting, or org-wide scope.
