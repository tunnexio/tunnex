# S2S-3: automatic recovery integration contract

Status: implemented locally following the user continuation direction. Versioned CP issuance, journal v2, controller switching and observed active-path reporting are integrated. Final source-matched native ARM64 packet qualification passed; maintenance PSK rotation is implemented and native ARM64-qualified too. Native AMD64 recovery/rotation proof and a fresh full CI gate remain outstanding. See S-S2S-3-completion.md for final evidence. This is not a claim that S2S-3 is complete.

## Pre-integration constraints

- `runtime_material.go` and `kernel_apply.go` require slot 1 selected. CP `runtime_store.go` produces that preference. Material identity and kernel allocation must not be rewritten in place to pretend a different delivery was received.
- `runtime_journal.go` uses format 1, immutable allocation/engine lineage and an explicitly checked phase graph. Save completes before mutation; uncertain persistence poisons the controller. Restart restores refusal. Journal contents never restore a lease, grant, PSK or readiness.
- `runtime_controller.go:installActive` permits only interface/reqid/peer/underlay tuple 0. Both route proof and this guard construction must change together before any alternate route can carry traffic.
- `runtime_status.go` reports transport evidence independently of permits. CP `tunnel_status.go` validates `selected` against delivery preference and returns slot 1 even when telemetry is absent. That existing field cannot silently become an observed failover result.
- Permit authority is process-local, nonce-bound to delivery/configuration/policy, at most 60 seconds and shortened by elapsed request/apply time. Existing authority cannot survive restart or clock/namespace qualification loss. Status freshness (90 seconds at the CP) is not recovery authority.

## Recommended authority model

Keep immutable CP configuration preference separate from a gateway's observed route selection. Deliveries that explicitly authorize recovery may select either of their two exact tunnel identities, but may not change prefixes, policy, peer identities, secret revisions or ownership. No operator-select-route endpoint is introduced.

Use a versioned recovery contract in material/capability negotiation. A configuration supported only by the recovery contract must never be issued to an older node. Fixed-path version 1 deliveries remain valid on upgraded nodes. Do not simply change all `ipsec_config_version == 1` checks to `>= 1`: admission, lease issuance, status validation and cleanup each need explicit supported-version handling. Cleanup must continue for an issued version even after ordinary activation eligibility is withdrawn.

Recovery remains serialized under the controller mutex. The reducer recommends; only the integration controller commits. Retain a healthy selected path with no automatic failback. Unknown, stale or discontinuous evidence causes refusal/reset, not a switch. The reducer uses a 3-observation/10-second hold-down and 5-second snapshot age; the controller samples every 5 seconds.

## Durable state and crash sequence

Recommend journal format 2 with a small nonsecret recovery record per delivery: completed selected slot, monotonically increasing switch sequence, pending source/target slots and explicit transition stage. Bind it to existing immutable delivery, ordered tunnel identities, allocation namespace and engine binding. It describes potential cleanup duty and last completed route state, never permission to forward. Keep ownership lineage for both tunnels throughout.

1. Remove this connection from active permits, install prefix refusal and read back the exact guard. Failure prevents route mutation. Other connections retain only their original remaining lease deadlines.
2. Obtain a fresh nonce-bound CP lease for the same current delivery/policy and revalidate runtime qualification and candidate evidence. If an already verified refusal is present, it may be reused only after current readback. Revocation, disable, stale policy or cleanup supersedes recovery.
3. Persist pending switch intent before the first route mutation. Under refusal, remove only exact old owned routes and install only exact target owned routes. Retain protocol 242, per-slot metrics 50001/50002, expected table/prefix/link checks and foreign-object refusal. Never use an unrestricted route replace that can overwrite a foreign route. Partial prefix movement is safe only while refusal remains verified.
4. Read back all routes, tunnel ownership, daemon/XFRM agreement, namespace, policy and guard; recheck fresh authority and the target's health. The candidate must still be Up. Do not require the failed source to be healthy merely to prove exact ownership/cleanup scope.
5. Persist completed selection while still refusing. Build permits from that selected slot's observed interface, reqid, peer and underlay. Compute remaining lease immediately before installation, then read back and recheck authority. If anything fails, keep/restore refusal and report no verified active selection.
6. Publish observed selection only after the completed proof. A persisted completed slot alone does not imply active forwarding after restart.

Crash at any stage restarts with prefix refusal before daemon or route recovery. Pending intent is reconciled using exact ownership inventory; ambiguous/foreign state is not adopted. No automatic rollback may reopen traffic with a saved lease. After fresh material/authority and proof, reconcile a completed slot, or finish/refuse a pending switch under the same contract. Save failure forbids subsequent mutation.

Upgrade must atomically validate and migrate v1 entries without discarding withdrawal templates or cleanup lineage. Downgrade must refuse v2 journals rather than erase them or resume fixed-path permits. Operator recovery must use a compatible binary to finish cleanup; deleting a journal is not a downgrade procedure.

## Observation and metrics

Preserve existing `selected` as configured preference for compatibility. Add an explicit nullable observed-selected slot plus selection observation time/sequence and contract version. Unknown/stale/unverified selection is null, including restart and switching. Transport Up/Down remains independently reportable and does not mean permitted or reachable end to end. The UI should show “Preferred” and “Active path” separately without claiming active path from configuration.

The CP validates exact org/node/certificate/delivery/desired/configuration identity and ordered tunnel identities as today. It accepts runtime selection only for an authorized recovery delivery, rejects out-of-order reports within that delivery, and clears/ignores it on stale receipt, revocation, desired revision change or cleanup. Telemetry never changes desired state or grants permission. Existing JSON status storage may carry this observation, but changed persisted semantics still require an explicit decision and regression coverage.

Gateway controller owns switch-attempt/completion/refusal counters and switch duration. Increment completion only after permit readback; no duplicate completion on telemetry retry. Use bounded reason labels, never PSKs, peer addresses or arbitrary error text. CP exposes validated observed selection, not a second independently inferred switch counter. Route metric ownership remains exact per tunnel; counters cannot authorize kernel mutation.

## Stop, revoke and cleanup

Disable/delete, certificate/org revocation, lease expiry and qualification loss win over pending recovery. Stop/revoke first withdraws permits; cleanup traverses both immutable tunnel lineages and any pending route-selection state. Retained prefix guards/range reservations and acknowledged cleanup semantics remain unchanged. A selected-slot report or switch completion is never a cleanup acknowledgement. Lost-response/absence-only cleanup must retain its prohibition on adopting or deleting foreign objects.

## Decisions requiring disposition before integration code

| Decision | Alternatives | Recommended |
| --- | --- | --- |
| Recovery authority in persisted delivery | Change behavior for every old delivery; add explicit versioned recovery authorization | Versioned authorization for new eligible deliveries; preserve fixed-path v1 behavior. Existing connections require explicit re-delivery under the new contract. |
| Persisted local selection and crash duty | Keep selection only in memory; mutate existing immutable allocation; versioned journal transition record | Journal v2 transition record, atomic v1 migration, downgrade refusal. Never persist lease authority. |
| Persisted status meaning | Reinterpret existing selected field; add observed selection alongside preference | Add nullable observed selection with sequence/version/freshness. Keep old clients' preference semantics. |

These are the new state/authority decisions. No new human permission is recommended: existing `ipsec:manage` controls connection configuration and activation; runtime recovery stays within an explicitly authorized delivery and current policy. If manual switching or per-connection failover toggles are desired, their configuration and permission contracts require a separate decision. Rotation, credential replacement and overlapping rekey remain separate work.

## Acceptance before enabling

Regression tests must first prove v1 compatibility, unsupported-version refusal, no field reinterpretation, out-of-order status rejection and migration refusal paths. Fault injection must cover every persistence/route/guard/readback boundary, all prefix subsets, old/new delivery races, expired/denied lease, discontinuity, target loss, foreign routes and concurrent cleanup. Test other connections' permit deadlines are never extended.

Native ARM64 and AMD64 tests must force source loss, show encrypted payload on the alternate after hold-down, prove no plaintext during switching or restart, retain the alternate while healthy, and verify disable/revoke/cleanup and WireGuard/OpenVPN coexistence. Build/unit/reducer tests alone cannot claim automatic failover or complete S2S-3.


## Local compatibility implementation — 2026-09-25

The recommended contract is being implemented following the user's continuation instruction. Optional `recovery_version` is appended to both private manifest types; absence preserves the exact legacy wire bytes and digest. Explicit recovery contract 1 is parsed; unsupported values refuse. Fresh authenticated recovery capability negotiates new recovery deliveries; already-issued manifests remain unchanged. Capability downgrade refuses material and permit renewal while preserving cleanup. Controller application now executes the authorized recovery contract.

Journal format 2 adds immutable contract authorization and a nonsecret selection transition record. Legacy entries retain absent ContractVersion (0), while recovery entries use 2. There is no eager open-time migration: adding a new authorized entry upgrades atomically using existing fsync/poisoning safeguards. Pending/completed transitions, sequence increments, initial slot 1, cleanup immutability and downgrade refusal have regression coverage. An independent pre-change encoder verifies legacy journal checksums.

Node and CP golden manifest tests pass, including unchanged legacy digest and identical recovery field ordering. Gateway eligibility regressions pass. Independent review found no remaining implementation blocker after the legacy checksum test was strengthened. These are compatibility/storage foundations, not an automatic failover completion claim. Next integration must implement refusal-before-switch and fresh observed active selection, then run native packet/crash tests. Deferred full CI remains outstanding. Changes remain local.

## Local integration evidence — 2026-09-25

CP/IPsec and HTTP focused race suites passed (16.537s and 10.134s), including real isolated database cases for immutable older delivery issuance, capability downgrade, ordered selection telemetry and retry freshness. Status metadata extends the existing two-element JSON array, preserving schema 161; both entries carry identical validated metadata. API/CLI generation uses pinned oapi-codegen 2.4.1; shared types use pinned openapi-typescript 7.4.4.

Full node IPsec race suite passed (10.139s). Kernel fault regressions cover every route-mutation interruption, partial retries, exact ownership and both-slot cleanup. Runtime fault regressions cover refusal readback, journal persistence, denied/short leases, route and target proof failures, pending retries and no failback.

Initial native ARM64 run `/private/tmp/s2s-recovery-native-0925a/result.json` records packet success and complete removal of its captured disposable resources. It used the previously qualified strongSwan package with a freshly compiled current test binary, not yet the final rebuilt production candidate. It proved primary interface loss, refusal/no plaintext, alternate encrypted TCP/UDP after hold-down, no failback, restart refusal and retained cleanup alongside WireGuard/OpenVPN. Native AMD64 evidence from S2S-2 does not qualify this new recovery behavior.

Web typecheck and 29 focused tests passed. Rendered synthetic desktop preview confirms separate Preferred path (slot 1 Down) and Active path (slot 2 Up), with collapsed troubleshooting and the existing theme. This preview does not write CP records or establish runtime health.

Recovery instrumentation is currently a bounded process-local snapshot of attempts, completed switches, attempts that encountered refusal, and total completion duration. Retries and healthy polls do not double-count; completion follows verified permit installation. No new metrics exporter or control-channel transport was introduced.

Active-path telemetry additionally requires read-only exact guard membership and rechecks lease, qualification, daemon and cancellation after slow proof. It cannot refresh a permit. Focused regressions cover expiry/withdrawal during observation.

Packet-fixture boundary: the gateway selects its alternate automatically, while the isolated remote peer emulator return route is moved explicitly by the harness. This proves the gateway path with a valid remote return route; it does not qualify automatic failover behavior on AWS, Fortinet, Cisco or another external VPN. The CP lease responder in the packet fixture remains synthetic; actual CP authorization has separate API/DB regression evidence.

## Final native ARM64 candidate — 2026-09-25

Image `sha256:09f41a95d15c367d7bb38e9e6671f1077b572726254465fe75fe168996884b7b` passed the expanded recovery fixture on native Linux ARM64 6.8. Test binary digest `dcf05bde36033a9ad7b58f6a7c998bf66df8739147e68a16d99be5e5bf10ddc6`; harness digest `8d4c188c6f08f6762500a24887db68893cc5526fc34e2fc9123c0cb28c67e85d`. Source hashes matched the production inputs. Receipt `/private/tmp/s2s-recovery-native-final-0925/result.json` records `passed:true` and `cleanup_complete:true`; build provenance is `/private/tmp/s2s-packaging-build-na2k32t9`.

The final fixture includes an injected failure after real route movement but before completed journal persistence, verified refusal, a new controller that resumes the pending target only with fresh authority, encrypted alternate TCP/UDP, no failback, a second completed-selection controller restart, resumed slot 2 and retained cleanup. This is controller-process restart proof, not host reboot or arbitrary external peer qualification. Both WireGuard and OpenVPN payloads remain functional throughout. The native AMD64 workflow now has a separate recovery step, but it has not been pushed or run.

Final host race checks passed for node control (7.935s) and IPsec (11.604s). The agent command test cannot compile for Darwin because existing Linux-only egress methods are absent; Linux candidate build succeeded. Web checks cover 63 tests across six files plus TypeScript. Full CI remains deferred and unverified.
