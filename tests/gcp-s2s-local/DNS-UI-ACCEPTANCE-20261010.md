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

## Subsequent normal admin Classic rotation

After root confirmed the independent emulated HA path's first granted packet, admin resumed normal login. The cloud inventory loaded; the recreated Classic connection was Applied and its menu contained Disable but no Rotate while enabled. Admin submitted Disable through the existing revision-2 CAS dialog, observed Cleanup pending, then refreshed and observed Disabled · guard retained. Only after that real cleanup acknowledgement did Rotate keys appear.

The rotation dialog showed exactly one Tunnel 1 password field. Admin submitted an owned private replacement key through the normal UI; no second slot or automatic Enable occurred. The server response passed the component's exact desired-revision 3→4 and disabled-intent checks, and the UI reported: “Keys saved. Update your remote VPN, then enable this connection.” Secret drafts cleared on submit. Enable remains held for root's external emulator peer key transition. No cloud rotation or DNS packet success is claimed.

The earlier runtime content search accidentally exposed an existing disposable emulator test key in tool output. That value is omitted from this receipt and replaced by this authorized rotation. Replacement data stays only in the ignored mode-0600 runtime fixture; no secret is committed.

Screenshot `/private/tmp/gcp-ui-emulated-classic-rotation-disabled.png` SHA-256: `3b6f6aa10249ede3f87dc1298411b5550e021da668bdf69adbce3ac038998183`.

## Subsequent old-key refusal and new-key recovery

Root explicitly authorized the isolated negative test with the external emulator peer retaining its previous key. Admin submitted Enable once from the revision-4 rotation readback, through the existing CAS/capability review; inventory reported Applying. Actual public single-tunnel status then reported Down, observed at 15:18:35. No optimistic retry or healthy assumption occurred. Root independently confirmed desired revision 5 and performed the old-key refusal probe before installing its private replacement peer fixture.

After root reported the new emulator peer staged/initiated successfully and the normal granted HTTP marker passed, admin refreshed actual tunnel status: exactly one Tunnel 1 was Up, observed 15:20:04. A normal inventory refresh reported Applied. The detail's revision 1 is the configuration revision; desired revision 5 was confirmed independently by root's normal API readback. Neither Applied nor Up alone is application traffic proof.

Root reports API source `90ef` and native source `15eb` for this test. Root's independent HA continuity proof was 30/30 successful HTTP probes during Classic disable, and HA traffic also passed during the Classic old-key test. Those packet observations belong to root's lab evidence, separate from this browser status receipt. All peer endpoints are owned internal emulator addresses; none of this establishes Google Cloud operation. DNS remains blocked by the genuine licence gate and no bypass occurred.

| Additional screenshot | SHA-256 |
| --- | --- |
| `/private/tmp/gcp-ui-emulated-classic-old-key-down.png` | `3bc16208973770d5d37557bcf6efdccbc0659cfc9bde5e7cd80f66b9399040f1` |
| `/private/tmp/gcp-ui-emulated-classic-new-key-up.png` | `1e5e7842d9577462eca71508448f80f8fe826f42fc961d870405eb6e7ad547d9` |

## Genuine local HA public status and roles

Admin, owner and member signed in normally and opened `gcp-ha-owned-emulator-1010`, actual owned connection `27e56a4f-b74e-43b2-9c7d-2ac10caf9c09` (root reported desired revision 2; UI configuration revision 1). All three read exactly two Up IPsec tunnels and Established BGP peers. Tunnel 1 uses `33.0.0.30`, inside `169.254.74.0/30`; Tunnel 2 uses `33.0.0.31`, inside `169.254.74.4/30`. Each peer reports one accepted prefix; installed counts are 1 and 0 respectively. The explicit installed route table shows only approved `10.74.0.0/24` via Tunnel 1. Rejected prefix counts are No data, not fabricated zero.

Fresh observations were 15:30:38 admin, 15:31:02 owner, 15:31:27 member. Member inventory had no Create connection or feature management action; the HA menu exposed Connection details only, with no Enable/Disable/Rotate/Delete. Member could read the same configuration/status/routes. No access grant or connection mutation was performed for these captures. Root was immediately notified that captures were complete so normal cleanup could precede the owned peer deadline. Reported tunnel/BGP/routes remain separate from root's actual packet fault/restoration/grant/revoke/expiry evidence. This is local emulator acceptance, not Google Cloud or single-host availability proof.

| HA screenshot | SHA-256 |
| --- | --- |
| `/private/tmp/gcp-ui-emulated-ha-admin-two-up.png` | `79b0011e7881f04e7fa57bcb766566ec3001788ed0567cf4601dfc20e4116edb` |
| `/private/tmp/gcp-ui-emulated-ha-owner-two-up.png` | `abff7d80ef983fe1ac6e551672702b8f0c42892b7bfa9c782fffe5341db171a7` |
| `/private/tmp/gcp-ui-emulated-ha-member-two-up-readonly.png` | `8ade8b34c2700d3164cf8ce78873937e0c6d1ec79c629ba3418789ccd1f47228` |

## Fresh lifecycle Site preparation

Normal verified owner registered `GCP lifecycle qualification local`, Site `01a1255c-323d-74ec-a690-ca42f8271a86`, in the existing owned organization. The initially requested local `10.71.0.0/24` advertisement remained pending: actual approval refused overlap with the preserved disabled HA baseline's `ipsec_remote` reservation. No eligibility/range guard was bypassed. After root explicitly chose `10.76.0.0/24`, owner removed only the fresh inactive pending71 advertisement, advertised76, and approved it through normal Range approvals. Inventory readback shows new76 Approved/routed and existing70 baseline preserved. The new Site has no assigned gateway; root owns its separate enrollment/lifecycle namespace. No new organization, CP-admin capability, entitlement, DNS, global setting, application grant, old identity/journal or gateway mutation occurred here. Remote75/24 must still pass root's actual provider preflight; this Site approval does not establish remote eligibility or traffic.

| Preparation screenshot | SHA-256 |
| --- | --- |
| `/private/tmp/gcp-ui-lifecycle-range-overlap-refused.png` | `5bbc8ca29fc16a9e9d9e038c3e44b7c16186a8c89c9dbad7161314934bb0de49` |
| `/private/tmp/gcp-ui-lifecycle-site76-approved.png` | `d99e08b7b3cd009a833cb96159e6de7244bc1fc22e3b2a3f9bf49fa613c5db6a` |

## Fresh native-source Classic role readback

Owner/admin/member used normal login and read `gcp-classic-lifecycle-owned-1010`, fresh connection `56125c63-10de-4e3c-8636-49a22d8c82e0`, tunnel `7265a26c-d8e3-4617-a70b-074247178211`, genuinely enrolled node `01a1255f-38b1-78a2-9937-0bfadae9fca8`, Site `01a1255c-323d-74ec-a690-ca42f8271a86`. Root reports native `aa72e085` source and unchanged API source; UI source remains `978bc7f76b95ca89f486bf8a58bdb6f2c047dd6a`. Desired revision2 is root's normal API confirmation; UI shows configuration revision1.

Actual inventory was Applied. Details showed local10.76/24, remote10.75/24, customer33.0.0.50 and peer33.0.0.60, with exactly one Tunnel1 Up; no BGP or invented second tunnel. Fresh timestamps (browser local IST) were 16:10:44 owner, 16:10:57 admin, 16:11:28 member. Member menu contained Connection details only, with Create connection count0 and no management actions. All checks were read-only aside from ordinary login/navigation: no grants, settings, DNS, capability or proof changes. The old recreated Classic row read Cleanup pending; no current old-lab Up claim is made. Controlled supervisor stop/proof/restoration was still pending at this capture; Applied/Up are distinct from actual packets and that lifecycle proof. Google/FQDN blockers remain.

| Fresh-source screenshot | SHA-256 |
| --- | --- |
| `/private/tmp/gcp-ui-fresh-classic-owner-up.png` | `41b9c0d08652c9bd9f96f3996bf72f09c89cba691447720ad2b7f22ee61c4119` |
| `/private/tmp/gcp-ui-fresh-classic-admin-up.png` | `aee7312d4617601a28725fab809fa9baec44fb4cb7334edcb98ee43da3328069` |
| `/private/tmp/gcp-ui-fresh-classic-member-up-readonly.png` | `faa85b646b795d70775a360a0b33bfbf79904b109d0400372f36ddefac1e24cd` |
