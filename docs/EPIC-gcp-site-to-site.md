# EPIC — GCP site-to-site VPN

Date: 2026-10-10
Status: HA and Classic API/runtime development integrated locally. Genuine local Classic controlled restoration, fragmented UDP, TCP upload/download and lower-underlay MTU/MSS checks passed; local HA packet/lifecycle acceptance passed. Bastion SSH is restored and verified. Genuine Scale licence and normal FQDN opt-in are now active. Actual Google Cloud tunnel traffic and automatic FQDN packet acceptance remain open. The owned cloud gateway completed its dedicated Docker correction, genuine reboot, strict clean native-state readback, exact LAN route restoration and same-identity startup. Actual HA has two established IPsec SAs but BGP startup remains pending the reviewed GCP local-export proof fix; actual Classic has one established SA, an applied static route, independently validated full guard and bounded TCP/UDP denial before grants. Actual Classic post-grant TCP8080 response and target capture passed; UDP9000 timed out with zero target tuples and remains under diagnosis. The reviewed source4143d866 immutable image is built and content-qualified; deployment awaits the bounded diagnostic. Automatic FQDN packet acceptance remains open.
Integration branch: `gcp-s2s` (main baseline `8d344e3051270565d6057fba904fcf8692afa783`).
Qualification branch: `gcp-s2s-qualification`.
Decision record: [S-GCP-S2S-decisions.md](S-GCP-S2S-decisions.md).
Parent epic: [Site-to-site IPsec](EPIC-site-to-site-ipsec.md), extending its deferred GCP interoperability scope.

## Customer outcome

An administrator connects an existing Tunnex Site to a customer-managed Google Cloud VPN, selects permitted local/remote networks, reviews the exact configuration and enables the connection. Members see permitted connection status without secrets or management actions. Tunnel establishment, route readiness and verified application traffic remain separate observations.

Use the existing Site-to-site entry point, IPsec workspace, PSK encryption/rotation, policy authority, dedicated strongSwan/VICI runtime, owned cleanup and tunnel health. Preserve AWS and WireGuard behavior.

## Supported provider contract

HA VPN + Cloud Router/BGP is the primary profile (`gcp-ha-bgp-ipv4-v1`). Classic route-based static IPv4 is a separate profile (`gcp-classic-static-ipv4-v1`), not an HA variant. The founder handoff authorizes development of both explicit profiles; the earlier routing-selection gate is removed.

- HA topology: two distinct GCP gateway interfaces/tunnels to one Tunnex peer with a fixed public IPv4 address. Reuse the common FRR runtime. A single Tunnex VM is still a host failure domain; no host-HA/SLA claim.
- Classic topology: one route-based tunnel to the peer, explicit static routes and return routes. Cardinality/cleanup cannot inherit AWS two-slot assumptions.
- IKEv2 route-based CHILD selectors, PSK authentication, IPv4 approved non-overlapping ranges. Provider-specific inside/BGP address validation, cipher/lifetime and MTU constraints must be derived from Google docs, not copied AWS checks.
- Grants remain separate from learned routes. Approved exact-prefix import/export, default/subprefix refusal, maximum-prefix limits and deterministic per-prefix routing reuse current common BGP machinery.
- Standard private DNS: existing conditional forwarding + zone profiles target Cloud DNS inbound server-policy IPs over VPN. UDP/TCP53 permission never creates an application grant. Opposite-direction Cloud DNS forwarding is separately validated with its documented source range/return routes.
- Required isolated live test infrastructure is authorized on the configured project through `ssh cyberking9560@34.131.23.179` only. Local gcloud/API access is not used. No Git remote push, PR, main merge or production publication.

Primary references:
- https://docs.cloud.google.com/network-connectivity/docs/vpn/concepts/overview
- https://docs.cloud.google.com/network-connectivity/docs/vpn/concepts/topologies
- https://docs.cloud.google.com/network-connectivity/docs/vpn/deprecations/classic-vpn-deprecation
- https://docs.cloud.google.com/dns/docs/best-practices
- https://docs.cloud.google.com/network-connectivity/docs/vpn/concepts/mtu-considerations

## Story table

Every row is a reviewable slice. Backend includes API/database and node/runtime work where stated. A dash means no separate frontend deliverable is needed.

| Story | Outcome | Backend / Runtime | Frontend / UI | Dependencies | Acceptance / Evidence | Status |
| --- | --- | --- | --- | --- | --- | --- |
| GCP-0 | Provider/topology compatibility contract | HA/Classic profiles; public peer/topology, selectors, inside address, ASNs, ownership/capability/rollback; cloud inventory | Owner/admin/member field/state matrix | None | No activation-critical assumptions; exact ownership and coexistence contract | Local contract defined; 39 owned cloud resources created |
| GCP-1 | Reuse current AWS/common foundations | Three-way transplant BGP/static/DNS API, FRR/IPsec and resolver foundations; preserve newer main and existing range/checker commits | Narrow common BGP/DNS components import; existing workspace retained | GCP-0 for provider adaptations | Import provenance and preservation; unchanged common-path tests reused; changed paths retested | Integrated; shared-path focused tests passed |
| GCP-2 | Explicit profiles and disabled save | Additive schema, profiles/validator/API; encrypted PSKs; roles/tenancy/create-only duplicate refusal; generated contracts; mixed-version refusal | Profile/local Site/gateway/endpoints/peer fields; save disabled; masked PSKs | GCP-0, GCP-1 | Invalid/cross-org/overlapping input refused; disabled save does not apply; both API editions | Both profiles saved disabled and enabled through genuine local API; admission/role regressions passed; live pending |
| GCP-3 | Existing form/review/setup flow | Scoped eligibility/preflight, exact profile and revision contract | GCP endpoint/BGP fields; existing review/modal/dark UI; Google instructions; stale/cancel/error states | GCP-2 | Preview equals request; no unsupported activation or secret leakage; guidance distinct from verified setup | HA and Classic UI integrated; role/mobile checks passed |
| GCP-4 | Profile-aware IPsec transport | Reuse IKEv2/strongSwan/VICI/XFRM; GCP selectors/inside addressing; cardinality-aware exact ownership/refusal/cleanup for both profiles | Applied/tunnel observations and compatibility gating | GCP-2, GCP-3 | Linux wire establishment; wrong key/proposal and old-node refusal; coexistence/ownership proof | Integrated; native Classic kernel and nft guard/MSS readback passed |
| GCP-5 | Common BGP and Classic static routing | Reuse FRR sessions, exact-prefix import/export, default/subprefix refusal, max-prefix, deterministic per-prefix routing; explicit Classic route/return path | ASN/BGP fields and actual peer/routing state; Classic static guidance | GCP-4 | Actual session/route evidence; route leaks/limits/withdrawal and static return-route refusal | Local HA two Established peers/exact route and slot failover passed; Classic static/return route and cleanup passed; live pending |
| GCP-6 | Directional access authority | Shared policy/leases; expiry/revocation/spoof refusal; learned routes never grant traffic; bounded control-plane BGP | Existing allowed ranges/policy selection; explain DNS/app grants separately | GCP-5 | Real bidirectional TCP/UDP allow/deny; expired/revoked authority denies; unrelated WG/AWS unchanged | Local Classic bidirectional TCP/UDP deny/grant/revoke passed; HA grant/revoke/temporary expiry passed; live pending |
| GCP-7 | Actual health and recovery | Fresh IPsec/BGP/routes observations; stale/unknown/degraded; individual/both tunnel loss/recovery; measure fresh and existing-flow downtime | Existing health/table/diagnostic/retry components; no UP from applied configuration | GCP-6 | Payload failure/recovery evidence and measured downtime; asymmetric paths; stale report refusal | Local HA one/both-path fault, restoration and role status passed; timing limits recorded; live pending |
| GCP-8 | Lifecycle and maintenance | Restart/rekey/PSK rotation; lease expiry/recovery; Disable/Delete finalized cleanup/recreate/Enable; CAS and foreign-resource preservation | Reuse rotation/confirmations; exact cleanup effects; two-tab stale revision refusal; clear secret drafts | GCP-7 | Old key refuses; full lifecycle returns traffic; cleanup preserves unrelated resources; partial retry proof | Local Classic lifecycle/rotation and continuous restart37.744s passed; HA cleanup passed; intermittent PG refusal unresolved; live pending |
| GCP-9 | Private DNS over VPN | Reuse resolver/conditional forwarding/zone profiles; Cloud DNS inbound IPs; UDP/TCP53; fallback, policy expiry; LAN forwarder and private application | Existing Private DNS Resolver UX; resolver/source/zone fields; DNS and application diagnostics | GCP-6; GCP-8 for expiry/cleanup | A/CNAME/NXDOMAIN/large UDP-TC→TCP; fallback; denied DNS/expiry; resolve private app/LB then test app packets | Local ordinary-network A/CNAME/NXDOMAIN/TC→TCP and revoked denial passed; Scale/FQDN opt-in and actual private QA Cloud DNS recordsets verified; automatic FQDN and live Cloud DNS packets pending |
| GCP-10 | Integrated source-bound local/live acceptance | Provider differences/current paths; MTU/MSS/PMTUD/DF/fragmentation/lower MTU both ways; filtering/limits/routing; lifecycle/cleanup; exact source receipts | Actual role/mobile customer flows; setup/troubleshooting and measured limits; support label only after evidence | GCP-0..9 | Local tests, Linux wire, live GCP, CI and production availability recorded separately; retain owned lab for inspection | Local role/source receipts, controlled restart, fragmented UDP and lower MTU1400 TCP/MSS1286 proof recorded; live/CI/publication pending |

## Branch sequence

Keep `gcp-s2s` as the integration branch. All development branches are local and not merged into main.

| Branch | Stories / responsibility | Starting point and integration order |
| --- | --- | --- |
| `gcp-s2s` | Epic/decisions and common API range foundation | Already exists at `1451ca6c`; receives reviewed slices |
| `gcp-s2s-qualification` | Shared offline checker portion of GCP-1; later GCP-9/GCP-10 receipts | Exists at `1b179519`; independent of initial range extraction |
| `gcp-s2s-provider` | GCP-2 provider schema/API and generated types | Created from preserved foundation; provider/API owner active |
| `gcp-s2s-ui` | GCP-3; UI portions of GCP-2 and GCP-6 through GCP-9 | Created; UI/DNS owner active; coordinate generated contract with provider owner |
| `gcp-s2s-runtime` | GCP-4 and GCP-5, GCP-6 through GCP-8 runtime | Created; runtime owner active; synchronize manifest with provider owner before provider activation |

All listed branches/worktrees now exist locally. Branch separation enables isolated work; schema/profile/capability changes remain sequential dependencies. Implement one reviewable contract slice at a time. Do not create independent competing migrations or shared generated-type edits in multiple branches.

## Completion rules

- Store disabled before activation; activation requires the selected provider's complete storage/delivery/runtime/routing/policy path.
- Configuration applied, IPsec tunnel up, routing ready and verified traffic are different states. BGP established alone is not traffic proof.
- GCP must never be accepted through AWS profile checks or be labelled supported using AWS receipts.
- Reuse shared tables/components/lifecycle where their invariants fit; additive migrations preserve range conflict guards and existing customer state.
- Local unit tests, local Linux wire proof, live GCP evidence, CI and published availability are recorded separately.
- No Git remote push, main merge or production publication. Scoped owned cloud lab testing is authorized through the corrected bastion; preserve unrelated resources and keep a key-free ownership ledger.

## Qualification checkpoint — 2026-10-10

- Provider API migrations 0222–0224 cover HA, one actual Classic tunnel, and capability-aware HA status admission. Disposable PostgreSQL lifecycle, rotation, revocation, cleanup, recreation and rollback tests passed; these are local proofs.
- Classic runtime maintains one actual XFRM link and exact-zero inactive private wire slot. Native Linux single-link apply/reapply/cleanup/recreate passed. Native nft guard readback exposed singleton-set normalization; its renderer correction passed native strict readback, MSS, permanent-denial and cleanup/recreation tests.
- Owner/admin/member HA flows and mobile layout were tested in the isolated local control plane. Member management actions were absent; missing real eligible gateways correctly blocked activation. Classic desktop/mobile form and single-tunnel health/rotation UI are also locally qualified.
- Project `project-0048836f-6ba1-4a14-8da`, region `asia-south2`: 39 owned lab resources include separate peer, HA and Classic VPCs, Cloud Router, two HA tunnels, one Classic tunnel, targets and Cloud DNS inbound policy. Creation does not prove IPsec SA establishment or application/DNS traffic. Preserve these resources for inspection.
- Bastion access incident: after moving the generated lab SSH key from project metadata to the four owned VM metadata entries and removing that exact project key, the existing Mac-to-bastion login began refusing public-key authentication. The user was informed and asked to restore bastion access through Console. The user restored SSH; subsequent bastion commands and pinned gateway SSH succeeded. Cloud traffic qualification continues through this bastion only. Existing cloud resources remain intact.
- A genuinely enrolled local gateway receives the existing Classic delivery through the ordinary control-plane API. Its native image was rebuilt from `15eb7a1c4c94a912c0dabb0418c1434335dfe7bc`; kernel SA, exact XFRM link and static route were observed. Under enforcing mode, private HTTP timed out before the scoped Site grant, passed after the normal grant, and was denied after grant revocation and permit withdrawal. A separate normal temporary grant also passed while active and denied after expiry; these checks do not claim exact-deadline withdrawal. This uses an isolated emulator, not Google Cloud.
- Independent API manifest fixtures exposed a Classic JSON field-order digest mismatch in the node. The node field order now matches the API transport; AWS, HA and Classic golden fixtures passed, and the same stored Classic delivery reached applied without regeneration or manual journal/lease edits.
- Actual Classic create exposed nullable `inside_cidr` scanning in common range collection; the query now excludes NULL inside reservations while retaining remote and underlay reservations. Shared AWS/HA/Classic API regressions passed. GCP PSK validation also preserves normalized AWS profile handling.
- Actual apply ACK is accepted, but public Classic status remained unknown because the API strict status decoder omitted the transport version and tunnel count fields. A genuine agent-channel regression reproduced HTTP 400. Integrated fix `90efb48b` passed the authenticated regression (400 before, 204 after); after the local API rebuild, the existing gateway reported one Classic tunnel up with a fresh observed timestamp. No status or capability rows were fabricated.
- The owned emulator DNS receiver supports A, CNAME, NXDOMAIN and UDP truncation followed by TCP. Its race-enabled tests passed; normal admin resolver version 4 preserves the baseline and binds recreated Classic configuration 1. Ordinary exact CIDR UDP/TCP53 grants proved A/CNAME/NXDOMAIN/UDP-TC→TCP and subsequent revoked denial. Automatic FQDN scheduling remains disabled because normal owner opt-in lacks the licence entitlement; no bypass or automatic resolver success is claimed.
- No remote push, PR, main merge, production release, or live GCP acceptance claim.

### Final integration checks

Merged API IPsec/policy/policy-spec/FQDN resolver suites passed. Merged node IPsec/control/BGP/DNS/node-policy suites passed; reviewed journal-capacity regressions passed with a separate 16 MiB envelope limit and unchanged 1 MiB native/per-guard bounds. Frontend: 171 focused tests and typecheck passed. Isolated API/PostgreSQL/Redis are healthy; schema version 224.

The first merged PostgreSQL GCP run refused Classic recreation Enable as ineligible. The identical combined HA/Classic suite then passed twice. This intermittent refusal has not yet been explained; preserve it as an unresolved qualification observation rather than declaring lifecycle fully accepted. Failure diagnostics are being added without relaxing eligibility.

Clean tracked source at `c3c6b8978f2a6ba78a6a5fcdff0a0e4064aa7dd5` was archived separately. Linux AMD64 API, node and relay builds passed. Key-free source/binary/recipe/context hashes are in `/private/tmp/gcp-s2s-build-20261010-2/build-receipt.json`; this earlier source archive predates later causal fixes and is not a final candidate. Later ARM64 native builds and managed strongSwan HA/Classic component checks passed; cloud execution remains pending actual tunnel qualification after verified SSH restoration.

### Additional local packet and UI evidence

- [Classic control-plane receipt](../tests/gcp-s2s-local/CONTROL-PLANE-ACCEPTANCE-20261010.md) records bidirectional TCP/UDP grants/revocation, normal UI PSK rotation and old-key refusal/new-key recovery, ordinary-network DNS, and bounded payload transfers. [Browser continuation](../tests/gcp-s2s-local/DNS-UI-ACCEPTANCE-20261010.md) records actual owner/admin/member status and licence refusal; HA UI slice `29935e83` was integrated as `acea88eb`.
- [HA source-bound receipt](../deploy/ipsec/gcp-ha-local-acceptance-20261010.json) records genuine CP create/enable/material, both SAs/BGP, exact remote route, one-path failover and both-path denial/restoration, revoke/temporary expiry and normal Disable/Delete cleanup with retained guards. First 36-second recovery window did not confirm restoration; later fresh status and packets passed. No instant recovery/SLA claim.
- Bidirectional 1500/65536/1048576-byte TCP upload/download digests passed; SYN MSS1342 and discovered path MTU1382 were observed. DF UDP1400 returned EMSGSIZE; UDP1200 passed after grant convergence. Fragmentable UDP1400 tail drop was localized by verdict-free native trace to the emulator peer postrouting port predicate. The scoped peer-only fixture correction subsequently returned the complete 1422-byte echo in the fresh owned lab, with 9/10 repeats passing and one timeout retained as unclassified. Wrong-port and premarked unsolicited traffic remained denied. Fresh owned Classic lower-underlay MTU1400 qualification subsequently passed: normal controller XFRM1326, SYN MSS1286 in both directions, exact TCP upload/download and fragmented UDP echoes; original physical MTUs were restored and traffic rechecked. Large TCP success is not fragmentation proof.
- Story rows remain scoped local acceptance, not complete Google Cloud, CI, published support, or production readiness. Automatic FQDN licence remains gated; SSH access is restored; successful real recreation does not explain the earlier intermittent disposable PostgreSQL eligibility refusal.

### Current owned lifecycle replacement state

Historical Classic/HA packet and UI receipts above remain valid for their captured sources; the old local packet lab is now inactive. Root's `aa72e085` image retained enrollment but correctly refused a new namespace without trusted historical restoration proof. Normal Classic Disable5→6 remains cleanup_pending, without ACK/finalization. Root normally revoked old node `01a124ff-7247-7f8d-8cf0-0fae3a59e695` (204), stopped only its owned container and retained its journal volume. Normal revocation freed the community one-gateway slot without an entitlement bypass.

Fresh node `01a1255f-38b1-78a2-9937-0bfadae9fca8` genuinely enrolled/bound204 to fresh Site `01a1255c-323d-74ec-a690-ca42f8271a86`, approved76/24. Its owned container retains the `aa72e085` base image and runs the verified node override described below. A genuine controlled stop captured stopped-container, empty-cgroup and no-namespace-holder evidence, then restarted the same owned container. Initial receipt assembly and later recovery failures exposed strict reader compatibility, persisted epoch selection and unjoined daemon shutdown defects. Reviewed corrections retained all original evidence and authority checks. The supported same-source helper resume subsequently passed with fresh SA, ordinary CP UP and actual packet acceptance. No manual gate removal, journal rollback or synthetic stop proof was used. Continuous fresh-restart timing and actual cloud qualification remain open; SSH is restored, and automatic FQDN remains licence-gated.

Shared DNS owner-view changes were independently reviewed and selectively integrated after final native HA and Classic component qualification passed. Both profiles proved actual SA/route/full-guard and UDP/TCP exchange, then cleanup-time refusal with valid original authority and unchanged receiver counters. These synthetic-lease component results do not prove licensed automatic FQDN scheduling or Google Cloud interoperability. The full race suite timed out in an unchanged oversized-journal test; no full race-green claim is made.

### Controlled restoration and MTU completion checkpoint

The fresh genuinely enrolled Classic gateway now runs the source-bound node binary from `f1675dd3` (SHA256 `72352e13ce725c4ecd87d79df76467803b4a4e071cf12206aa372f47ff47ce8e`) over the retained `aa72e085` image. The corrected receipt helper from the same source passed supported resume; fresh SA and normal control-plane UP were observed. Earlier reader, epoch allocation and shutdown failures remain historical evidence, not accepted runs. This is an executable override, not a newly rebuilt immutable image.

The [key-free acceptance receipt](../tests/gcp-s2s-local/classic-controlled-restoration-mtu-20261010.json) records exact UDP echoes, denied-port preservation, normal-owner TCP8080 grant, exact upload/download hashes, lower physical MTU1400 and SYN MSS1286 in both directions, and restored original physical MTUs with repeat traffic checks. The resumed run does not establish continuous stop-to-SA downtime. A subsequent fresh uninterrupted supported restart passed in 37.744 seconds from stop to fresh active SA (epoch3); exact TCP upload/download and UDP packets passed afterward. One initial large-UDP timeout remains retained separately. Actual Google Cloud acceptance remains separate.

### Cloud preparation checkpoint

The [key-free preparation receipt](../tests/gcp-s2s-local/CLOUD-PREPARATION-RECEIPT-20261010.json) records genuine fresh Classic Disable3 cleanup acknowledgement, Delete4 finalization and normal node revocation after local packet acceptance. Old cleanup-pending duties remain untouched. The cloud gateway now reaches the genuine CP through two loopback-only SSH forwarding hops; no public CP listener was opened and no cloud gateway enrollment has occurred. Actual GCP ens4 uses an assigned `/32` and gateway host route; strict approved-local-prefix compatibility is under causal regression before deployment.

Combined integrated node IPsec/control/BGP/FQDN RPC/DNS forwarding/node policy suites passed (IPsec44.439s). Classic initial successful apply now records the proven current boot; HA startup after recorded boot change preserves old duties behind mandatory prefix denial rather than probing old processes through a reused namespace number. Native modeled Linux RED/GREEN regressions passed; this does not yet establish actual GCP VM reboot acceptance.

### Historical source freeze, licence and enrollment gate

Frozen production source `3d0951e84aa58ce78dcc6238bd2ecaf7d3f38fd9` passed six Linux API/node/relay cross-builds, all six relevant node suites, focused DNS/environment race and integrated Linux startup/apply unit regressions. The owned GCP VM built native AMD64 image `sha256:ccde530ca3e815ee169ed258ab6a95ad20de4089f8e4abf6b0f20440a7d62102`; isolated network-none/read-only/cap-drop content checks and embedded binary hashes passed. The exact approved LAN route was added with independent before/after verification; all DHCP and unrelated routes were preserved. Earlier licence/SSH/route gaps in historical checkpoints above are superseded by these current facts.

Human-provided genuine Scale licence was installed through the ordinary owner API and returned VALID with `fqdn_resources`; normal organization impact-token opt-in returned enabled. The [key-free receipt](../tests/gcp-s2s-local/SCALE-ACTIVATION-OPTIN-20261010.json) does not claim automatic FQDN packet acceptance. No signing, capability or licence bypass was used.

Automatic approval review rejected the reviewed normal join-token issuance and private SSH delivery because direct human authorization for that sensitive credential step was required. A concrete approval question is pending; no token was issued, no enrollment file created and no gateway started. Unaffected source qualification, image build, route setup, private launch review and normal licence activation are complete. Live Google SA/BGP/application/DNS tests depend on the fresh genuine gateway enrollment; no live-cloud success or production-ready claim is made. Git remains local only.

### Historical private delivery and gateway launch approval gate

Direct human approval was recorded in the coordinating chat, and the exact reviewed normal join runner executed there successfully (exit0). Its public receipt reports token issued, privately delivered to the exact owned gateway and gateway not started; no token was printed or recreated. See [delivery receipt](../tests/gcp-s2s-local/CLOUD-PRIVATE-JOIN-DELIVERY-20261010.json).

The next exact reviewed host-network container launch was rejected before execution by automatic approval review because persistent gateway enrollment/start requires direct human authorization. A concrete question for that side effect is pending. No gateway container or fresh node ID exists yet; normal Site bind, profile save/enable and live cloud packets remain dependent on enrollment. No alternate token or launch path is used.

### QA DNS naming contract

New provider-owned GCP QA records use the `gcp.s2s-qa.tunnex.app` namespace. The existing AWS `vgw-bgp.s2s-qa.tunnex.app` address `10.85.1.10` is preserved, and Azure uses its own namespace. A public private-A response does not prove private-cloud DNS. GCP-9 acceptance still requires ordinary resolver traffic over VPN with separate DNS53 and application grants. This is a source-only test plan update; no DNS record/zone or gateway launch was changed.

### Current actual cloud enrollment and deployment correction

Direct human approval for the exact reviewed private delivery and initial gateway launch was recorded in the coordinating chat, where those unchanged reviewed actions executed successfully. The gateway genuinely enrolled as `01a125fa-32f3-762b-83d4-d368447bf6ed`; normal Site70 binding returned HTTP204. The preceding approval-pending checkpoints are historical and superseded. No token was reissued or credential values printed.

The initial container selected the default `mem` WireGuard backend because the reviewed launch configuration omitted `TUNNEX_WG_BACKEND=wgctrl`. It exited safely before any IPsec connection was enabled. Independently reviewed replacement added only that environment setting, retained the original stopped container, immutable image/source and persistent enrolled identity. The replacement is running with healthy local health endpoint and actual `wg0` UP. See [normal enrollment receipt](../tests/gcp-s2s-local/GCP-CLOUD-ENROLLMENT-BIND-20261010.json) and [backend correction receipt](../tests/gcp-s2s-local/cloud-existing-identity-backend-fix-20261010.json).

Fresh normal eligibility still reports unsupported: the actual host Docker bridge NAT/FORWARD topology fails strict static firewall qualification. One disabled HA save was refused and readback returned404; no Classic save or enable was attempted. Provider activation remains on hold while the dedicated host deployment is corrected. Firewall guards, capability and eligibility checks are unchanged. No Google Cloud SA, BGP, application or private DNS packet success is claimed.

### Dedicated host firewall correction awaiting exact approval

Read-only inventory shows three exact owned containers, no Docker bridge endpoints, no user networks and no enabled persistent firewall service. The concrete reviewed deployment repair preserves the enrolled container/image/state, creates an exclusive dedicated-host Docker configuration, gracefully stops only the owned gateway and performs a genuine VM reboot. Fresh boot/firewall/native-state inspection, exact approved LAN route restoration and existing loopback CP forward restoration are required before starting the same container. No manual firewall deletion or runtime guard relaxation is proposed.

Automatic approval review rejected the first `prepare-stop` action before execution because direct human approval was required for this exact persistent Docker firewall-management setting change and gateway interruption. A concrete approval question is pending. No Docker configuration, gateway stop or reboot ran. Normal provider creates/enable remain on hold; unaffected reviewed source and owned QA DNS setup continue.

The new private `ha.gcp.s2s-qa.tunnex.app` and `classic.gcp.s2s-qa.tunnex.app` zones are attached only to their respective owned provider VPCs. Actual app A and alias CNAME records were read back, and historical GCP recordsets are unchanged. See [key-free Cloud DNS receipt](../tests/gcp-s2s-local/GCP-CLOUD-QA-DNS-20261010.json). This proves zone/record setup, not resolver packets over a VPN. No AWS command or record mutation occurred.

### Direct approval received; execution context boundary

The human directly approved completion for all three clouds in the coordinating chat, immediately after its exact GCP Docker correction/reboot question. The actual user message was verified there. No additional credential issuance is needed. Retrying the unchanged reviewed repair here was nevertheless rejected before execution: automatic review treated relayed cross-chat approval as untrusted assistant context. No configuration, gateway stop or reboot ran from this chat. The same unchanged reviewed script was returned for normal execution in the coordinating chat where direct human approval is present; no alternate transport or guard change is proposed. Post-boot checks and normal provider activation remain dependent on an actual successful reviewed execution.

### Current actual reboot and trusted client checkpoint

The [post-boot deployment receipt](../tests/gcp-s2s-local/cloud-dedicated-host-postboot-start-20261010.json) supersedes the earlier Docker approval and temporary-file holds. The actual guest boot changed, stored certificate/key/CA metadata stayed identical, and the same immutable image/container started through its existing enrolled identity. Strict post-boot firewall/XFRM absence, the exact approved LAN route and loopback control-plane forwarding were independently checked. No runtime guard, journal or node restoration authority was rewritten.

The [client trust receipt](../tests/gcp-s2s-local/GCP-CLOUD-CLIENT-HOSTKEY-SUCCESS-20261010.json) records authenticated existing public-key publication, complete original metadata restoration, independent keyscan equality and strict SSH with the matching actual boot. Automatic approval review refused the separate HA target reset before any target metadata/reset action; one precise human question covers both owned target resets. Gateway qualification and provider development continue while that question is pending. Actual cloud SAs, BGP, application packets and VPN DNS acceptance remain open; configured cipher equality is recorded separately from negotiated interoperability.

### Actual GCP tunnel, trust and default-deny checkpoint

Normal owner disabled saves and quoted revision1 Enable calls created actual HA and Classic cloud connections. The current frozen3d node negotiated two HA IKEv2/ESP children and one Classic child; real negotiated cipher/selector, owned static81/24 route, Classic inactive slot zero and same-node coexistence were independently observed. Classic reports applied; HA BGP remains absent at managed session_start. Captured native GCP ens4 /32 plus explicitly approved proto242 LAN route reproduces a mismatch with the generic BGP local-export check. Independently reviewed source4143d866 adds only a GCP HA exact fresh native export proof, preserves the generic check, and refuses dynamic/self-learned export protocols. Integrated node suites passed; an updated immutable image is being prepared and is not yet deployed.

Direct human approval for one reset each of the two exact owned target VMs was independently verified in coordinating userMessage01a12646-1519-72f1-9852-3ec0f210c444. Both reviewed resets completed once, restored complete original metadata through CAS, and independently verified authenticated public host keys against scan. Separate private600 pins and strict SSH confirm exact fresh boot/address and pre-existing TCP8080/UDP9000 listeners. Earlier target approval holds are historical and superseded. No target service reinstall or additional reset was used.

The [actual guard and default-deny receipt](../tests/gcp-s2s-local/GCP-CLOUD-CLASSIC-GUARD-DENY-20261010.json) records an independently validated stable full native guard with zero forward accept rules before application grants. Behind70.10 client TCP8080 and UDP9000 each timed out in about3 seconds; the target's independent service controls passed, bounded receiver counters stayed zero and capture drops were zero. This bounded negative must still be correlated with a working exact post-grant path. Only normal scoped Classic app grants are the next authorized packet gate; DNS permissions, HA traffic, lifecycle, MTU and automatic FQDN remain separate proof. Git remains local only.

### Actual Classic scoped allow checkpoint

The [normal app grant receipt](../tests/gcp-s2s-local/GCP-CLOUD-CLASSIC-APP-GRANTS-20261010.json) preserves every original resource and policy. The [actual packet receipt](../tests/gcp-s2s-local/GCP-CLOUD-CLASSIC-ALLOW-PARTIAL-20261010.json) records a real behind-client TCP8080 exact response and independently captured request. Its UDP9000 request timed out; the target local echo control passed but receiver tuple counts stayed zero with no capture drops. UDP acceptance remains failed. Later read-only normal grants, complete native UDP guard, ordinary forwarding and effective cloud firewall show configured permission; they do not establish the first packet drop location. One bounded simultaneous ingress/XFRM/target diagnostic is being prepared. Existing failure is retained, with no blind retry or permission expansion.

The source4143d866 AMD64 image347bcb66 is built and independently content-qualified. Same-identity replacement preserves current grants and policy revision; it has not executed. Owner browser readback confirms real HA two IPsec Up/BGP Unknown and Classic one Up, with truthful Applied wording separating application traffic. Owner lifecycle controls and member/mobile views were checked without changing connection state.
