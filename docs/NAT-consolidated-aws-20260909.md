# Consolidated NAT candidate: AWS qualification in progress

Server content commit `0b1dd1554221e9c00cd610c2c14a7f5048b14cc3`;
client content commit `55f4267763d5ba906a187e0a120067b0fb910256`.
No release, push, merge, or exact-head CI completion is claimed.

Account 735391218823/ap-south-1 and exact CP/gateway instance identities verified.
Only the dedicated `tunnex-byodb-neon-20260906b` API and
`nat-product-gateway-20260909a` were replaced; no infrastructure deleted.

## Deployment and regression evidence

- CP migrated through 141, dirty=false. Candidate API initially healthy;
  HTTPS health returned status=ok. Codegen drift check passed locally.
- Candidate Linux enterprise test executable ran against the actual hosted
  walk database inside AWS CP. Credential tests and device/owner/org quota
  concurrency tests passed. Durable mailbox creation exceeded its unchanged
  five-second transaction deadline on two isolated attempts. NOT a pass.
- Rolled gateway back to retained executable. API rollback initially failed its
  startup migration against the newer schema. Retained additive 141 tables and
  restarted the former API with an explicit `TUNNEX_AUTO_MIGRATE=false` rollback
  override; HTTPS health then returned status=ok. No schema downgrade/data deletion.
  Current rollback requires `compose-rollback141.yaml` in addition to the existing
  base and lockfix files. Do not omit that override when restarting this old API.
- Investigating excess full-topology reads: gateway selection loaded DNS,
  subnets, device pool and Kubernetes inventory unnecessarily. Shared hub-member
  reader extraction keeps existing HA derivation and five-second deadline.
  Local connectivity/node race suites pass; hosted regression is still pending.

## Mac helper artifact correction

First install attempt mistakenly packaged a Go library archive instead of the
helper command. launchd could not execute it. Corrected build explicitly targets
`./cmd/tunnex-helper`; verified Mach-O arm64 executable and native caller auth.
User reran the installer. Helper now responds Down. Installer validates format,
version, hashes and post-bootstrap service status; original working binary remains
at `/private/tmp/tunnex-helper-finish-rollback.HCfznf/previous` on this laptop.
Installed signed executable SHA256:
`ea1baaabad730b8df9d43194606083051652cb32449dae83f3aab40db682230f`.
No new-helper end-to-end pass yet. No private keys, tokens or credentials recorded.
