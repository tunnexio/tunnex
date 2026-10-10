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

Original connection: `5d91018f-dc08-4c2b-9241-663be55863b8`. Recreated connection: `3a48c7ba-fa02-477d-970a-d7b5167a305b`. Scope: local10.70.0.0/24, remote10.73.0.0/24; all synthetic public underlay addresses stay on an internal Docker network.

Private inputs remain local mode0600. Key-free operational receipts are under `/private/tmp/gcp-s2s-control-plane-lab-20261010-1/`; they are runtime evidence, not a signed certification or automated CI result.

DNS: normal admin UI saved resolver context version3 while preserving its direct baseline. Its IPsec profile used configuration revision1 and assigned gateway LAN source10.70.0.2 for UDP/TCP53. Four resolver resources were created normally; owner feature opt-in was refused because the local deployment lacks the fqdn_resources licence entitlement. No query or DNS packet acceptance claim; no entitlement bypass.

Limits: reverse initiation, MTU/PMTUD, PSK rotation and HA BGP/failover acceptance remain pending. A prior disposable PostgreSQL recreation refusal remains unclassified; this successful real local workflow does not explain that earlier intermittent observation. Cloud acceptance is blocked by bastion SSH public-key refusal. Labs remain owned and retained for inspection; no push, PR, main merge or production publication.
