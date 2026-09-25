# S2S-3 completion evidence

## Scope and remaining acceptance

The approved slice includes two-tunnel recovery, independent status and diagnostics, restart refusal/recovery, maintenance PSK rotation and existing lifecycle preservation. Maintenance rotation was approved on 2026-09-25. Work is on `story/site-to-site-connectivity`; the user has approved publication and CI dispatch. New native AMD64 qualification has not yet passed. S2S-3 cannot be described as fully qualified until native AMD64 recovery/rotation and a fresh full CI run pass.

## Implemented behavior

- New recovery-capable deliveries authorize either exact tunnel while old deliveries remain immutable and fixed-path compatible. Journal v2 records pending/completed route duty, never saved permission.
- A failed active path is refused before route movement. Fresh observations, hold-down, exact ownership, current authority and permit readback are required for alternate traffic. Healthy alternate remains selected; restart restores refusal and requires fresh authority.
- UI reports independent Up/Down/Unknown, configured Preferred path and independently verified Active path. Compact troubleshooting disclosures use the existing theme. Actual timed guard membership and post-proof lease validity are required for active telemetry.
- A verified owner/admin can rotate one or both write-only PSKs only when disabled and never delivered or exactly cleaned. The transaction advances desired/secret revisions, preserves the partner and historical manifests, and audits no secret. It stays disabled until explicit Enable after remote configuration. Same-current-key replacements are rejected.
- A transaction-bound immutable rotation record and commit-time coherence prevent partial child/parent updates, stale CAS, constraint-flush ordering bypasses and missing audit. Audit retention and historical user removal are not blocked by new live foreign keys. Exercised rotation prevents unsafe schema downgrade.
- When both tunnels are verified Down, bounded negotiation retry under refusal allows corrected remote keys to recover. Unknown evidence or a healthy alternate does not trigger this retry. A new lease is required after negotiation.

## Verification

Final native Linux ARM64 6.8 candidate:

- Image: `sha256:4325baaa8978acd0597dafcd188f9a0cf2920db4249e0ee2286d52bfae42a404`.
- Test binary: `cda855ecee7a51f2a1f3cd35f93ffdbe7248ec44ad95f19de63a3bdca9b606b0`.
- Harness: `e9cfa1664137291b2ecd67bf8035637b37650c2b502bcffb507a4990fcd19e6b`.
- Receipt: `/private/tmp/s2s-rotation-native-final-0925/result.json`, `passed:true`, `cleanup_complete:true`.
- Build provenance: `/private/tmp/s2s-packaging-build-fz9owfq4`; staged production hashes matched tested source.

The fixture proves encrypted TCP/UDP and ESP after failover, refusal/no plaintext at transition boundaries, pending route-change crash recovery, completed-selection controller restart, no failback, old-key authentication refusal with no SAs, new-key negotiation and traffic, and cleanup across both credential generations. WireGuard/OpenVPN payloads continue. The peer emulator return route is orchestrated by the harness; the CP lease responder is synthetic. Separate real CP/API/database tests cover authority. This is not host reboot or external AWS/firewall acceptance.

Node IPsec/control final race suites passed (11.059s and 7.501s). A mutation removing retry was rejected by the new behavioral regression. Full web suite passed 1,643 tests across 137 files; an additional safe-successor revision regression subsequently passed with all 16 rotation tests. TypeScript and production build also passed after that guard addition. Synthetic browser inspection confirms password-only rotation, cleared fields, success guidance and remaining disabled state without CP writes.

HTTP rotation authorization/parsing/redaction races passed (10.084s). Independent database constraint-order mutation controls reproduce the old bypasses and reject them with schema162 (8.910s). Observed PostgreSQL advisory-lock races cover rotation against Enable/Delete in both orders and old material waiting behind rotation. Sealing, second-write and audit failures roll back atomically. The final combined IPsec/HTTP/DB race matrix passed twice (92.846s / 28.214s / 6.178s); actual timestamp-schema checks passed for open and enterprise editions. Two earlier failures before rotation or in the older capacity fixture did not reproduce in subsequent runs; their exact cause remains unproven. `/private/tmp/s2s-rotation-final-validation.txt` records them explicitly. No production freshness rule was weakened.

## Previously reported full-CI failure

Completed run `35997595000` was read once at final verification, not monitored or rerun. Its two failures were the missing standard `set_updated_at` triggers on IPsec connection/settings tables and an auth census suffix-regex false positive on `RuntimePrincipal`. Migration162 supplies the standard triggers. AST-based census retains exactly one canonical agent constructor while excluding unrelated DTOs, with open/enterprise regressions. Passing local regressions does not claim remote CI green.

## Boundaries

No cloud resources, customer PSKs, real connection seeds, PR, merge or deployment. Process-local recovery counters have no new exporter. Rotation intentionally has whole-connection downtime; old backups/WAL and remote devices are outside live-key removal guarantees. AWS customer acceptance and later providers remain subsequent epic slices.

## Local control plane

Updated the already-owned `tunnexs2scp0924` project after verifying exact PostgreSQL/Redis containers, project labels, network and ports. Private pre-upgrade backup: `/private/tmp/s2s-local-cp/before-rotation-1790307971382596000.dump`. Schema is 162 with dirty=false; `/healthz` returned status ok. Inventory remained 3 organizations, 4 sites, 11 nodes, 0 IPsec connections. No seed or reset occurred. Vite remains on localhost5198. The synthetic preview is explicitly separate from real gateway state.

The user approved committing/pushing the reviewed S2S-3 changes and CI fixes to `story/site-to-site-connectivity`, and running native AMD64 qualification and full CI. No new CI run is being monitored; the user asked to report its status themselves.
