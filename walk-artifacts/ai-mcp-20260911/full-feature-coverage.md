# Expanded AI feature walk

User requested complete AI Gateway/MCP/AI Agent feature coverage, followed by simpler user journeys. This ledger distinguishes live evidence from tests and unsupported/unconfigured prerequisites. No universal green claim.

## Current result (supersedes chronological remaining-work notes below)

The configured GPT-5 chat, workload identity, MCP policy/OAuth, agent rotation/provenance, network-template and JIT control-plane scenarios listed here have live evidence. Streaming, JIT cancel/reject/idempotency and natural expiry are now proved. Non-chat modes are unconfigured by user disposition. Remaining qualification boundaries are natural OAuth token refresh, interrupted rotation recovery/old runtime credential rejection, and JIT-specific enforced dataplane expiry. These are not marked passed: the OAuth test grant was explicitly revoked and the enforcing test org was explicitly cleaned up. Trigger for those proofs: a dedicated resilience/production qualification run with a new consented provider session and disposable enforcing lab. Prior template dataplane proof does not substitute for JIT expiry dataplane proof.

Current fixes are on story/ai-mcp-walk-fixes. Web85c56bd5 deployed on CP; API unchanged. All1517web tests, typecheck and production build passed. Independent narrow review found no regression. No push, merge or release performed.

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

### Usage, disable/re-enable and workflow evidence

- Usage UI attributes exact test call to workload:1request/88tokens. Cost absent and incomplete-pricing warning present. Spend-by-model shows empty because engine model breakdown is cost-only; wording falsely implies no usage and needs improvement, not invented billing data.
- Replacement key and instance enroll after prior key revocation. Test threshold1USD with unavailable pricing yields403; removing threshold via browser numeric-field fill did not actually clear rendered value (still1). Cause not yet attributed to product versus browser input tool; streaming attempt under this unchanged guard also403, so no stream success claimed.
- Disabled workload refuses token issuance/new enrollment. Re-enabled workload permits existing instance fresh token issuance; pre-disable token returns403 on models and previous enrollment key remains401. Workload currently enabled with threshold1; replacement instance is not yet revoked. Final cleanup pending.
- Signed synthetic workflow on original fixture host: signing key registration204; first assertion201verified; replay201unverified/replay; modified tool claim201unverified/bad_signature. Agent Activity shows verified chain and hides tool/workflow/resource/initiator for unverified claims. Private signing key remains host-only.
- User confirmed only GPT-5 chat exists; non-chat model modes should be marked unconfigured, not blocked awaiting credentials or claimed tested.
- JIT opt-in toggle was rejected by automatic approval review as requiring exact Demo setting approval. Specific question pending. Enforcement remainsOff.

### End-user and final workload state

- My models shows single-org VPN Base URL /ai/v1, exact org/model identifiers and SDK example. Browser-session Call model returned BROWSER_WALK_OK (92tokens). Raw response JSON is currently the default output: simplify answer/usage and move technical fields behind details in UI follow-up.
- Test workload disabled again after recovery proof, fresh token issuance401. Final replacement instance2fe07878-8e58-4bfe-9106-600be8ac0caa revoked via UI; all4 instances and all3 keys revoked. Disabled workload record intentionally retains audit/usage evidence; there is no workload delete API.
- JIT-specific opt-in approval remains pending. No enforcement change was made. JIT and natural OAuth refresh are not marked passed; non-chat modes explicitly unconfigured per user.

### Approved JIT continuation and streaming

- Latest user approved the exact temporary Demo JIT opt-in. UI pending request01a0919b-ca5d-7f4d-aad3-47070df5572a for fixture agent and ai-mcp-walk-private resource approved, history pending→approved, managed policy appeared on full reload. Revoke removed that rule on reload and restored0rules. JIT restoredOff with0pending/0approved; enforcement remainedOff throughout.
- Found two display bugs: policy table stays stale after JIT mutation; future expiry renders Expires0sago because it uses the last-seen age formatter. Approved correction recorded in the decision document before code.
- Original test agent streamed GPT-5 through an in-memory runtime identity exchange201, inference200 text/event-stream,5dataevents, DONE marker and exact STREAM_WALK_OK response. No runtime/provider credential was printed or persisted by the test.
- Remaining JIT cancel/reject/natural expiry uses a separate temporary CLI credential (existing user CLI state untouched), to be revoked at completion. This proves control-plane lifecycle only; Demo enforcement remainsOff.

### Final JIT results and deployment

- Cancel request01a091a0-cb28-7843-9597-d1b98f86dda0→cancelled; reject01a091a0-d032-7971-836a-aa939d1ae6f9→rejected. Duplicate creation with the same idempotency key returned the same request for all3cases.
- Request01a091a0-d51a-7543-9d79-3151a9ecc9e9 approved for300seconds. Natural server expiry2026-09-11T18:05:32.625658Z; subsequent read showed history pending→approved→expired, no database/clock manipulation. Rules list0after expiry.
- Deployed web85c56bd5 from artifact sha256da8fb0adedd79d33b8dbb8700d0546e3ed20fb0edeb55e4db0e3442e1d00b454; image manifest liste71a235400319befe8d41c3789ac24c1c3374081c7b2f3baf0af4abab363ac1e. Restricted rollback override on CP ai-mcp-fixes-20260911/rollback-before-jit-85c56bd5.yml.
- New UI request01a091a7-7d82-7e47-b67f-160cf96d7664 proved approve displays1activeJIT rule without reload and revoke displays0without reload. Exact expiry rendered11/09/2026,23:35:32for expired request; future timestamp rendered correctly for new approval.
- Final API restore: enabledfalse,pending0,approved0. Network enforcementOff throughout. Temporary CLI credential6017883dd0e6 logged out/revoked without warnings; user CLI state untouched. CP web healthy and HTTPS healthzstatusok.
