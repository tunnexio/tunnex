# Local emulated Classic DNS UI receipt — 2026-10-10

This continuation records normal browser configuration and licensing refusal. It does not prove DNS packets, Google Cloud DNS, or application authorization. UI source remains `978bc7f76b95ca89f486bf8a58bdb6f2c047dd6a`; running CP source reported by root was `90ef` during this continuation, without a per-action binary receipt. Environment and actual organization, Site and gateway IDs are recorded in `UI-ACCEPTANCE-20261010.md`.

## Normal role paths

- Admin signed in normally, added the separate `Local emulated Classic DNS` profile to the existing resolver context. Version 3 retained the direct baseline `GCP local DNS configuration acceptance`, suffix `private.gcp.local`, endpoints `10.70.0.53:53` UDP/TCP.
- New profile uses suffix `localemulated.gcp.lab.test`, receiver `10.73.0.10:53` UDP/TCP, exact owned gateway LAN source `10.70.0.2`, and original emulated Classic connection `5d91018f-dc08-4c2b-9241-663be55863b8`, configuration revision 1. This receiver is an isolated local emulator.
- Admin created four normal FQDN resources: `app`, `alias`, `tcp`, and `absent` under that suffix, representing A, CNAME, UDP truncation/TCP fallback, and NXDOMAIN checks. All remain `Resolving, awaiting server result`; their TCP port 80 descriptors create no application access rule.
- Owner signed in normally and opened Settings → Features → FQDN → Review and enable. The server reported no `fqdn_resources` licence entitlement. Enable was disabled; preview reported zero enforcement-ready rules. Review was cancelled. Enforcement remains off, and no bypass occurred.
- Root subsequently disabled/deleted/recreated the emulated connection through its normal API lifecycle. Admin reopened the existing profile editor: the deleted connection was absent from the enabled picker, with Select an enabled connection selected and activation disabled. No old binding was silently redirected.
- Admin selected new connection `3a48c7ba-fa02-477d-970a-d7b5167a305b`, fetched configuration revision 1, and saved version 4 through Activate profiles. Both original direct profile and the four resources remained preserved. Source, suffix and endpoints remained unchanged.

## Limits and continuation

Resolver queue SQL joins an organization with `fqdn_resources_enabled`; off enforcement therefore explains no queued DNS queries or receiver counter file. No successful A/CNAME/fallback/NXDOMAIN result is claimed. Resume only after genuine licence entitlement and normal owner opt-in, then compare actual resolver reports and receiver counters.

Rotation preserves the existing disabled-only guard. An enabled connection cannot open Rotate keys. Normal sequence: Disable with exact desired-revision If-Match; wait for cleanup eligibility; refresh; open Rotate keys. The form rechecks connection, provider and actual tunnel identities. Classic submits one real tunnel ID through POST rotate-psks with `expected_desired_revision`; success remains disabled and increments desired revision by one. Secret drafts clear on submission. A conflict or uncertain response freezes retry until close/refresh. Peer key transition and explicit Enable are separate steps. No active rotation was submitted in this continuation.

The subsequent cloud inventory remained loading during inspection; a normal browser reload then reached sign-in with `unreachable`. No conclusion about active tunnel state was derived from that incomplete UI response. Root subsequently confirmed the owned API exited with OOM status 137 at 09:41:52 in the shared 1.913 GiB Colima host and restarted only this API. This is an observed lab host limitation, not evidence of a frontend defect.

## Screenshot integrity

Temporary screenshots exclude credentials and PSKs.

| File | SHA-256 |
| --- | --- |
| `/private/tmp/gcp-ui-emulated-ipsec-dns-configured.png` | `d70a861b89567bceaa8c32e9f5a8588384eba9b05425dc02eee2b38890bb7fe6` |
| `/private/tmp/gcp-ui-emulated-fqdn-entitlement-refusal.png` | `5980d75b43e2a375105609ec9be20a930ff757464f9e3cd66988f1c3fc992e77` |
| `/private/tmp/gcp-ui-emulated-dns-rebound-v4.png` | `c7f46643274db0e2d32cf1e0ccc5328db7529566c989ad3478fd194e7b5ec3d7` |
