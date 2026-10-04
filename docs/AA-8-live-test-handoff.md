# App Access live-test handoff

Status: preparation for the user-requested phase after all local first-release stories and final integrated acceptance. This file is not evidence that AWS deployment or the live browser test has occurred. No Git remote push is part of this handoff. Current qualification is tracked in [AA-8 evidence](AA-8-development-evidence.md).

## Required topology and acceptance

Use the existing AWS control-plane machine only after verifying its current identity, architecture, installed source/schema, storage, backup/master-key custody and gateway inventory. Transfer the reviewed source/artifacts by SCP after local acceptance. Do not provision replacement infrastructure as part of this handoff.

Run a private test web origin on a separate existing machine reachable by its assigned gateway. Use another machine's ordinary browser with no Tunnex/VPN client. That browser must use the public App Access URL; it must be unable to reach the private origin directly. Explicitly verify both facts rather than inferring origin isolation from a successful proxy request.

The live walk must cover normal login, exact user/group grant, reviewed readiness/publish, allowed app content, denied user and denied direct public URL, fresh and already-open request behavior after revoke, confirmed application disable and retained app-scoped events/audits. Use an independent test identity so administrator console sessions and unrelated grants remain intact. Add rendered configured IdP login to the supported journey; native clients and fake-IdP handlers alone do not satisfy it.

## Deployment prerequisites

- Source and artifact hashes must match the locally tested candidates and recorded build/toolchain provenance; retain prior binaries and configuration for controlled rollback.
- Verify the target architecture and trusted signed descriptor before selecting immutable API/proxy image digests. Local test signing keys, unsigned qualification images and synthetic digest adapters are not production signing or registry-distribution proof.
- Record the existing schema and completed installation generation. Use only the qualified same-schema image-replacement procedure; schema rollback or ordinary unmanaged reinstall is not implied.
- Use separate known registrable domains for the public app and HTTPS console. Validate DNS, registered app hostname coverage, browser-trusted public certificate and exact gateway/private-authority SANs. Do not bypass browser security warnings or broaden gateway trust.
- Provision a dedicated proxy credential and private TLS files through the supported offline procedure. Do not transfer local synthetic credentials, root CA keys, browser cookies, session tokens or local database snapshots as production inputs.
- Preserve the external restore volume and its identity separately from PostgreSQL/Redis backups. Verify there is no pending marker and authority is completed before intentional listener startup. Recovery requires new proxy credentials, logins, checks and republish.
- Keep gateway/authority listeners private with direct TLS; publish only the reviewed public app edge. Explicitly restrict origin ingress to the gateway path and verify the browser machine's direct-origin denial.
- Preserve existing VPN/AI configuration, gateway enrollment keys and unrelated workloads. Record existing listener/port conflicts and rollback artifacts before changing services.

## Qualified limits and evidence boundary

The local path is single proxy/single connector, TLS1.3/HTTP1.1. Known-length forms/uploads, assets, registered redirects/cookies, SSE, WebSockets and bounded transfers are exercised. Chunked request bodies remain unsupported. Sixteen positive SSE streams and seventeenth-stream refusal are a bounded capacity test, not a general throughput/memory guarantee. Revocation cannot remove delivered bytes or undo origin-accepted side effects.

Static public/gateway certificate replacement requires controlled proxy restart; no hot reload or HA claim. Certificate expiry closes admitted client-certificate channels through the bounded lease watchdog. Live enrolled automatic certificate renewal, production CA issuance, signed image distribution and the target topology must be evidenced explicitly where required; a child test fixture does not establish them.

The final local evidence and current artifact table must be refreshed after qualification completes. Keep raw tokens, cookies, private keys and backups in private owned artifacts; publish only nonsecret proof and hashes. AWS host/network discovery and any remote mutation remain the next coordinated phase, not an action performed by this document.

## Current tested local artifacts

Current platform is Linux/arm64, built with Go1.26.8. The private source/artifact manifest `tests/app-access-local/.runtime/aa9-source-artifact-handoff.json` binds2265 selected source files, WIP status and baseline Git HEAD to this qualification. Its source-scope SHA256 is `3da7aa3d0bfd561d831f65a748fd5e50f3718e4b983e869b6400c3ba5e5b7d52`; it is not a committed release SHA. No secret/session artifact belongs in the future transfer.

| Artifact | SHA256 |
| --- | --- |
| Native API |267fef1d22ee154e02d34536369132fff3db797f4a98c23604624cab57ffd7c3 |
| Gateway |1542548440b6b2498ff5201bd556c44bf9a8c95c460d1b12a0290788d4f23edb |
| Standalone shipping proxy candidate |d5cf8ed4f2ca80d332977b59ea3acc9033615822f192f6062fbceaa2c411d1b7 |
| Same-schema operator helper |c8f0b5515a0f7ce95445b4b3f72ee812a413fd57bdfa95780c9cdcfd400b65a6 |

The shipping proxy candidate is retained privately as `.runtime/bin/aa9-tunnex-app-proxy`. The paid API/proxy test executables are nonshipping fixtures and must not be deployed as production services. Current local main readback is clean173, completed installation1, Payroll active17/authority9. Fresh strict normal launch/compatibility and new five-protocol synthetic self-revoke pass on the staged runtime; maximum observed closure1.934seconds. All nine stories are locally accepted. Production signed publication/distribution and the subsequent authorized remote live-test topology retain their explicit proof requirements.

## Subsequent local UI quality pass — 2026-10-04

[UI quality evidence](AA-8-ui-quality-evidence.md) records the rendered workspace comparison, responsive and keyboard checks, lifecycle proof and final web gates. Current Payroll is active revision17/authority10; final web suite has1881passed plus2expected failures across152files. The preceding source/bundle hashes and authority9 readbacks are historical snapshots before this UI pass. No remote action is implied.
