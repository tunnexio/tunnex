# Expanded AI feature walk

User requested complete AI Gateway/MCP/AI Agent feature coverage, followed by simpler user journeys. This ledger distinguishes live evidence from tests and unsupported/unconfigured prerequisites. No universal green claim.

## Live evidence this continuation

- Original Demo restored as sole membership after disposable network/OAuth org deletion.
- Original fixture agent credential rotation: runtime revision1→2/current, WireGuard revision1→2/current. Runtime remained active/connected/ready; no manual credential/key edits.
- Workload `full-walk-readonly-20260911`, ID097c6e38-f28a-4ca3-9bc0-ecc7534fee33, configured only GPT-5.
- Single-use key `full-walk-single-use`, IDcb5a355c-f1f8-48e6-98d4-bc000319f40c, created through UI (24h, ephemeral). Secret only in mode0600 scratch file; never committed.
- CLI local isolated state enrolled instanced5d0dc2e-02e1-49be-b691-48e108b036eb. Independent second state with same key refused401. Runtime proxy modelnot-granted→403; configuredGPT-5→200 WORKLOAD_OK, usage11prompt/77completion/88total.
- Workload instance key rotation via CLI returned same instance, generation2.

## Coverage remaining

- Workload reusable key, multiple replicas, enrollment limit, key-only vs instance-sweep revocation, individual revoke, disable/re-enable, replacement key.
- Usage/cost readback by known subject, filters and threshold refusal.
- JIT pending/approve/reject/cancel/revoke/expiry and network proof.
- Signed workflow provenance and invalid-signature display.
- Model-mode mismatch and streaming. Only GPT-5 chat is configured; real non-chat provider operations require matching models/credentials and are not proved by mocked responses.
- OAuth natural refresh not exercised; connected inventory/read tool/provider revoke are proved in network-oauth-continuation.md.
- Rotation recovery after interruption and old-credential refusal remain distinct from successful rotation.

## UI findings for the next simplification pass

- P2: Access JIT list fetches only50, drops cursor and lacks state filters, hiding older actionable requests.
- P3: Agent JIT card explains availability but no direct link to request/approval controls.
- P3: Non-chat model use panel lacks operation-specific invocation examples.
- MCP OAuth connected UI currently says tokens are never sent to agent, but runtime OAuth leases intentionally deliver transient access tokens in memory. Copy must distinguish provider refresh/client secrets from transient access leases.
- Preserve existing workload key/instance lifecycle surfaces and consequences; they exist and are not missing.

Secrets and runtime state remain only under /private/tmp/tunnex-workload-fullwalk (restricted). This test workload must be disabled/revoked after the remaining lifecycle proof; original customer model grants remain unchanged.

### Additional workload lifecycle proof

- Reusable key12653845-c924-4cfe-85d0-e4ebaa37da09 (24h, limit2) enrolled replicasde2674af-738a-4b79-ac41-c67a45c82c7c and347fd1a3-4708-478c-9d12-5f90797458d0. Third independent enrollment refused401.
- Revoked spent single-use key without instance sweep: its existing instance still issued a token (discarded, never printed).
- Revoked reusable key with instance sweep: both replicas' next token issuance refused401; UI readback revoked.
- Individually revoked original instance: next token issuance refused401. All3 test instances now revoked; both enrollment keys revoked.
