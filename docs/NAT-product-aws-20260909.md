# NAT product candidate — live AWS checkpoint

2026-09-09. User authorized deployment and testing, requesting continuation until
the customer test or a genuinely human-required blocker. This is NOT a completed
native traffic walk, signed release, final CI result, or merge-ready claim.

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
  default-drop. Application traffic evidence is still pending.

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
| Mac helper, not installed | 7a5a2a1b8deaba358038228c4703248e8c04c5bc4a9c43646fa35b4cf4c28288 |

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
