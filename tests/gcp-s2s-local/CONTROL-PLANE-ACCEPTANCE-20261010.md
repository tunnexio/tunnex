# Genuine local Classic control-plane acceptance

Environment: isolated Docker lab with a genuinely enrolled gateway and external strongSwan peer emulator. This is not Google Cloud qualification.

Node source: `15eb7a1c4c94a912c0dabb0418c1434335dfe7bc`. Image index: `sha256:858600540bb9765e03445038240b377cd27d1c039fbc0980ab1ee5075865bd4f`. API source: `90efb48b`; Linux ARM64 binary SHA256: `2c708326881a9a41de21b63121888a87269eced09f63d2dbebe6692eaf179e81`.

| Check | Actual result |
| --- | --- |
| Genuine delivery | Same stored Classic delivery accepted after node manifest field-order correction; no regenerated delivery or manual journal/lease edits |
| Native transport | One owned XFRM interface, static route, two ESP states and three broad-selector policies observed |
| Status | Normal agent report rejected with HTTP 400 before API metadata decoder fix; accepted afterward, one tunnel up with fresh observed timestamp |
| Default TCP denial | Behind-gateway client timed out before any application grant under enforcing mode |
| Scoped TCP grant | Normal Site-to-resource TCP18080 grant returned the owned private HTTP marker |
| TCP revocation | Immediate access remained within existing permit; subsequent probe timed out after withdrawal; no exact-deadline claim |
| Temporary grant | HTTP marker while active; timeout after normal grant expiry and permit withdrawal |
| Default UDP denial | No UDP9000 response before grant |
| Scoped UDP grant | Normal Site-to-resource UDP9000 grant returned the exact owned echo marker |
| UDP revocation | Subsequent UDP probe timed out after normal revoke and permit withdrawal |
| Disable | Normal If-Match revision2 → disabled3; genuine cleanup ACK produced retained_guard and owned ESP state was absent |
| Delete | Normal If-Match revision3 → deleted4 after cleanup ACK |
| Recreate | Fresh connection and tunnel IDs, same scope and private PSK; normal Create201 disabled1 → Enable200 revision2 → applied and fresh up |
| Recreated traffic | Normal exact-client CIDR TCP grant returned private HTTP marker through new tunnel |
| Independent reverse TCP/UDP | Both denied before exact normal grants, returned owned markers after grants, then timed out after normal revoke |
| Normal UI PSK rotation | Disable revision3/cleanup ACK → one-slot Rotate disabled4 → Enable5; old peer key yielded zero SA and denied HTTP; new key restored marker and fresh one-tunnel Up |
| Bidirectional payload | TCP uploads/downloads 1500, 65536 and 1048576 bytes passed length/SHA256 checks |
| MSS / DF | Forward and reverse SYN MSS1342; discovered path MTU1382; DF UDP1400 EMSGSIZE, UDP1200 echo passed after grant convergence |
| Ordinary-network DNS | Exact CIDR TCP/UDP53 grants: A, CNAME, NXDOMAIN and UDP TC→TCP A passed; both protocols timed out after revoke/withdrawal |

Original connection: `5d91018f-dc08-4c2b-9241-663be55863b8`. Recreated connection: `3a48c7ba-fa02-477d-970a-d7b5167a305b`. Scope: local10.70.0.0/24, remote10.73.0.0/24; all synthetic public underlay addresses stay on an internal Docker network.

Private inputs remain local mode0600. Key-free operational receipts are under `/private/tmp/gcp-s2s-control-plane-lab-20261010-1/`; they are runtime evidence, not a signed certification or automated CI result.

DNS: normal admin UI saved context version3, then version4 rebound only the emulated profile to recreated connection configuration1 and assigned gateway LAN source10.70.0.2, preserving the direct baseline. Four FQDN resources remain awaiting automatic resolver results; normal owner opt-in was refused for missing fqdn_resources licence entitlement. No entitlement bypass or automatic resolver acceptance. Separately, actual ordinary-network DNS queries from behind-gateway client10.70.0.10 through exact normal CIDR TCP/UDP53 grants reached receiver10.73.0.10:53: A/CNAME/NXDOMAIN/TC-to-TCP passed. Root observed both UDP/TCP timeout after revoke and updated the key-free checkpoint with those actual denial results.

Evidence: [UI continuation and screenshot hashes](DNS-UI-ACCEPTANCE-20261010.md), [bounded payload fixture](PAYLOAD-RECEIVER.md), and key-free `/private/tmp/gcp-s2s-control-plane-lab-20261010-1/packet-checkpoint.json`. Forward/reverse MSS captures are `classic-mss-capture.txt` and `reverse-mss-capture.txt` in that directory. Packet receipt's `secret_printed:false` describes its own packet harness; the UI receipt separately records accidental old disposable key exposure and its subsequent rotation. No secret values are included here.

HA: [source-bound local receipt](../../deploy/ipsec/gcp-ha-local-acceptance-20261010.json) records genuine authority, two SAs/BGP peers, route10.74/24, one-path failover, both-path denial/restoration, normal revoke/temporary expiry, and Disable/Delete cleanup with retained guard and absent remote74 route. UI owner/admin/member saw two Up/Established peers and exact route, member details-only. Classic rotation maintained independent HA HTTP continuity30/30. These are local emulator observations; they are not Google Cloud proof.

Limits: fragmentable UDP1400 timeout remains under causal fixture postrouting tail-fragment investigation; lower-underlay-MTU qualification remains in progress. Large TCP digest success and DF evidence do not complete fragmentation/PMTUD coverage. HA first36-second recovery window was not confirmed; later recovery passed. Automatic FQDN remains licence-gated. A prior disposable PostgreSQL recreation refusal remains unclassified; this successful real local workflow does not explain that earlier intermittent observation. Cloud acceptance is blocked by bastion SSH public-key refusal. Labs remain owned and retained for inspection; no push, PR, main merge or production publication.

## Owned lifecycle replacement checkpoint

The earlier Classic/HA packet, BGP, policy, rotation and DNS network receipts remain valid historical observations of their stated sources. They do not describe current old-lab availability. When the `aa72e085` native image retained enrollment but ran in a new namespace, it correctly refused missing trusted historical stop/restoration proof. No capability or proof was fabricated. Normal Classic Disable advanced desired revision 5→6, but cleanup remains pending: no cleanup ACK or finalization is claimed.

Root normally revoked old node `01a124ff-7247-7f8d-8cf0-0fae3a59e695` (HTTP204), then stopped only its owned container, retaining the old journal volume. That normal revocation freed the community one-gateway admission slot; no licence bypass occurred. Existing old identity/journal scope remains retained and the old packet lab is inactive.

A fresh identity `01a1255f-38b1-78a2-9937-0bfadae9fca8` genuinely enrolled in the same organization and was normally bound (HTTP204) to Site `01a1255c-323d-74ec-a690-ca42f8271a86`, `GCP lifecycle qualification local`, approved local `10.76.0.0/24`. Container `tunnexgcps2slifecycle1010-gateway-1` runs the `aa72e085` image (root reported image identifier prefix `1b179`), with unique owned underlay `33.0.0.50` and LAN `10.76.0.2`. Partial image identifier is recorded as reported, not a full digest verification. No manual capability/stop-proof state was injected.

GCP-aware supervisor slice `d783a550` was reviewed and integrated; root reports 22 Python tests and Go helper checks passed. Scripts are prepared on the actual Colima host, but no controlled supervisor stop/proof/restoration has yet occurred at this checkpoint. Fresh actual packet acceptance and controlled restoration remain pending, as does old cleanup. [Normal owner Site preparation](DNS-UI-ACCEPTANCE-20261010.md#fresh-lifecycle-site-preparation) records the preserved baseline and actual overlapping71 refusal before approved76 replacement. FQDN licensing and real Google Cloud SSH blockers remain unchanged.
