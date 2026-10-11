# EPIC — GCP site-to-site VPN

Date: 2026-10-10
Status: The owned gateway now runs source `0249f7cf8804a7d6b4e1f82bf4dbf42b887bdfe7` (imagec0ca/CIDf15e) after normal same-enrollment replacement; prior9c3 payload/story proofs remain historical; the owned local API now runs completion-clock fix `0b3df50e1144cc888a1c567c11ee6566e4663cea`. Actual HA and Classic application TCP/UDP, Classic grant expiry denial, HA DNS A/CNAME/NXDOMAIN, explicit EDNS1232 large-answer UDP-TC→TCP fallback, and normal automatic Classic FQDN generations passed. Actual isolated owner/admin/member desktop/mobile views passed. Controlled MTUv7 passed normal and lowered-path fragmented UDP round trips and 1MiB TCP upload/download; physical MTU1460 and original target source were restored, while all inner interfaces retained1326 with full guard proof. Live HA full recovery/both-path loss, remaining PSK lifecycle and restart/rekey/fault remain open; isolated two-tab CAS passed. Normal0249 startup and measured SAD6/HA6,7/Classic20 passed; Fresh full native/guard plus Classic/HA TCP/UDP recovery passed; controlled rekey and HA fault qualification remain open. This is owned-lab deployment, not production publication. Historical failures are retained. Git changes remain local; CI and production publication are separate.
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
| GCP-2 | Explicit profiles and disabled save | Additive schema, profiles/validator/API; encrypted PSKs; roles/tenancy/create-only duplicate refusal; generated contracts; mixed-version refusal | Profile/local Site/gateway/endpoints/peer fields; save disabled; masked PSKs | GCP-0, GCP-1 | Invalid/cross-org/overlapping input refused; disabled save does not apply; both API editions | Both explicit profiles saved disabled and enabled through the genuine local API and actual owned GCP gateway; admission/role regressions passed. Actual old-key rejection/new-key recovery passed; remaining restart/rekey/fault/CAS qualification is tracked in GCP-8 |
| GCP-3 | Existing form/review/setup flow | Scoped eligibility/preflight, exact profile and revision contract | GCP endpoint/BGP fields; existing review/modal/dark UI; Google instructions; stale/cancel/error states | GCP-2 | Preview equals request; no unsupported activation or secret leakage; guidance distinct from verified setup | HA and Classic UI integrated; role/mobile checks passed |
| GCP-4 | Profile-aware IPsec transport | Reuse IKEv2/strongSwan/VICI/XFRM; GCP selectors/inside addressing; cardinality-aware exact ownership/refusal/cleanup for both profiles | Applied/tunnel observations and compatibility gating | GCP-2, GCP-3 | Linux wire establishment; wrong key/proposal and old-node refusal; coexistence/ownership proof | Integrated; native Classic kernel and nft guard/MSS readback passed |
| GCP-5 | Common BGP and Classic static routing | Reuse FRR sessions, exact-prefix import/export, default/subprefix refusal, max-prefix, deterministic per-prefix routing; explicit Classic route/return path | ASN/BGP fields and actual peer/routing state; Classic static guidance | GCP-4 | Actual session/route evidence; route leaks/limits/withdrawal and static return-route refusal | Actual deployed9c3 HA BGP/owned route and Classic static route passed; both profiles passed scoped TCP/UDP. One-peer secondary route/guard/packets passed; full recovery cycle remains open |
| GCP-6 | Directional access authority | Shared policy/leases; expiry/revocation/spoof refusal; learned routes never grant traffic; bounded control-plane BGP | Existing allowed ranges/policy selection; explain DNS/app grants separately | GCP-5 | Real bidirectional TCP/UDP allow/deny; expired/revoked authority denies; unrelated WG/AWS unchanged | Actual9c3 Classic and HA scoped TCP/UDP allow and pre-grant denial passed; Classic temporary90-second allow/expiry denial passed. Separate later restoration passed; no continuous availability claim |
| GCP-7 | Actual health and recovery | Fresh IPsec/BGP/routes observations; stale/unknown/degraded; individual/both tunnel loss/recovery; measure fresh and existing-flow downtime | Existing health/table/diagnostic/retry components; no UP from applied configuration | GCP-6 | Payload failure/recovery evidence and measured downtime; asymmetric paths; stale report refusal | Local one/both-path qualification preserved. Actual one-peer loss selected secondary7 with strict full guard and TCP/UDP packets; exact fault cleanup verified. Recovery overlap observer and actual both-path loss/recovery remain open |
| GCP-8 | Lifecycle and maintenance | Restart/rekey/PSK rotation; lease expiry/recovery; Disable/Delete finalized cleanup/recreate/Enable; CAS and foreign-resource preservation | Reuse rotation/confirmations; exact cleanup effects; two-tab stale revision refusal; clear secret drafts | GCP-7 | Old key refuses; full lifecycle returns traffic; cleanup preserves unrelated resources; partial retry proof | Historical lifecycle/rotation proofs preserved. Actual9c3 grant expiry allow/deny passed; immediate restored-native refusal and original overallfalse retained, separate later restoration proof passed. Normal Disable/rotation/old-peer authentication refusal and full packet denial passed; Disable6 cleanup acknowledgment/native withdrawal passed. Old-key rejection and new-peer recovery passed with measured index20 full guard and Classic/HA TCP/UDP. Same-enrollment0249 restart/cutover recovery and isolated CAS passed; controlled rekey/HA one+both-path fault remain open |
| GCP-9 | Private DNS over VPN | Reuse resolver/conditional forwarding/zone profiles; Cloud DNS inbound IPs; UDP/TCP53; fallback, policy expiry; LAN forwarder and private application | Existing Private DNS Resolver UX; resolver/source/zone fields; DNS and application diagnostics | GCP-6; GCP-8 for expiry/cleanup | A/CNAME/NXDOMAIN/large UDP-TC→TCP; fallback; denied DNS/expiry; resolve private app/LB then test app packets | Actual HA A/CNAME/NXDOMAIN and authenticated resolver-only TCP/UDP53 authority passed. Explicit EDNS1232 UDP-TC→TCP100A diagnostic passed; original no-EDNS timeout preserved. Automatic Classic app/alias/NX generations passed after APIclockfix; FQDN-only IPsec app authorization unsupported |
| GCP-10 | Integrated source-bound local/live acceptance | Provider differences/current paths; MTU/MSS/PMTUD/DF/fragmentation/lower MTU both ways; filtering/limits/routing; lifecycle/cleanup; exact source receipts | Actual role/mobile customer flows; setup/troubleshooting and measured limits; support label only after evidence | GCP-0..9 | Local tests, Linux wire, live GCP, CI and production availability recorded separately; retain owned lab for inspection | Actual DF1354 success/1355 ICMPMTU1382 refusal/MSS1342 and controlledMTUv7 normal/lowered fragmented round trips plus1MiB upload/download passed. Final physical1460/inner1326 full guard and original-source cleanup passed; v1..v6 failures retained. Isolated owner/admin/member desktop/mobile views passed; actual isolated two-tabCAS passed with normal finalized tombstone and full original baseline preservation. CI/publication separate |

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

New provider-owned GCP QA records use the `gcp.s2s-qa.tunnex.app` namespace. The existing AWS `vgw-bgp.s2s-qa.tunnex.app` address `10.85.1.10` is preserved, and Azure uses its own namespace. A public private-A response does not prove private-cloud DNS. GCP-9 acceptance requires ordinary resolver traffic over VPN with authenticated resolver-only DNS53 authority and separately granted application traffic; the later actual context proves that additional ordinary DNS53 resource rows are unnecessary. This is a source-only test plan update; no DNS record/zone or gateway launch was changed.

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


### Actual source4143 replacement and fresh Classic packets

The normal same-identity replacement retained the old stopped container and all previous failure receipts. Its strict preflight and fresh refusal checks passed before creating the new immutable image container. An initial create attempt correctly refused because normal shutdown removed the owned WireGuard route and tables. A separately reviewed continuation proved that exact cleanup while preserving unrelated routes and the original refusal.

[Fresh Classic packet evidence](../tests/gcp-s2s-local/GCP-CLOUD-CLASSIC-POST4143-PACKETS-20261010.json) records actual behind-client TCP8080 response in8.838ms and UDP9000 exact echo in4.629ms, each with an independently captured target request and zero capture drops. The full11-resource/10-policy baseline and both connection configurations remained unchanged. These are packet observations, not an uptime claim.

HA currently reports both tunnels Down and no BGP route. Native observation showed only Classic transport loaded in the fresh daemon, while the retained HA journal remained Applied. Ordinary restart must restage its guarded transport rather than infer daemon state from retained links; a source regression is under development. DNS and lifecycle stories remain open.


### Current refusal checkpoint and finite diagnostic preparation

The [saved runtime checkpoint](../tests/gcp-s2s-local/qualification-20261010/lifecycle-source/expiry/current-runtime-refusal-checkpoint.json) preserves the actual HA retry stage and retained allocation, independently from Classic tunnel Up. A fresh complete native capture passed structural production readback but had no application allows and all six permit sets empty. The [expiry archive](../tests/gcp-s2s-local/qualification-20261010/lifecycle-source/expiry/README.md) distinguishes failed helper cycles, exact baseline restoration, normal temporary-policy sweep and the later zero-write preflight refusal. None is claimed as completed expiry acceptance.

The same-VPC private target completed DNS TCP appA response validation; the gateway TCP path remains unqualified. Its first instrumented helper refused before query because of a native VICI counter-format mismatch. The narrowly corrected parser and [one-case diagnostic coordinator](../tests/gcp-s2s-local/qualification-20261010/lifecycle-source/dns/README.md) passed independent review. Execution requires a newly measured full positive guard; the preparation does not weaken current refusal or qualify a future image. The [next replacement checklist](../tests/gcp-s2s-local/GCP-NEXT-SAME-IDENTITY-REPLACEMENT-PREPARED-20261010.md) requires fresh source/image/argv/identity evidence and complete baseline preservation.


### Current source13007 expiry and recovery checkpoint

The [native build provenance](../tests/gcp-s2s-local/qualification/13007c40-clean-local-build-20261010/native-actual/receipt.json) and [normal replacement receipt](../tests/gcp-s2s-local/qualification-20261010/lifecycle-source/replacement-13007/REPLACEMENT-13007-RECEIPT.json) bind the deployed source, immutable image and enrolled identity. Fresh shutdown proved exact owned cleanup with unrelated topology preserved; startup independently reproved mandatory prefix denial before ordinary controller reconstruction. Observed tunnel/BGP readiness does not establish sustained application availability.

The [failed expiry archive](../tests/gcp-s2s-local/qualification-20261010/expiry-13007-failure/README.md) retains the complete actual cycle. Temporary TCP/UDP policies were created with a genuine 90-second deadline, then the complete native capture refused while the journal held two guard records. Original grants were restored through the normal API. After the genuine deadline, the temporary IDs were already absent through normal expiry cleanup and the complete original 9-connection/13-resource/12-policy/configuration baseline matched exactly. Fresh full native guard showed all six permit sets empty; restored TCP/UDP acceptance failed. No expiry or traffic-recovery success is claimed.

Read-only causal work uses the actual unmodified source13007 environment inspector and ordered native transcripts. A successful individual sample and exact offline replay do not explain earlier refusals. Further bounded observations and narrow source regressions must prove the cause before a corrective deployment. No journal, authority, lease or guard qualification was relaxed. Automatic FQDN writes, HA positive grants and lifecycle mutations wait for packet recovery.

### Address-lifetime refusal reproduced; recovery acceptance remains open

On frozen source 13007, the historical 18:36 checkpoint had all six permit sets empty after normal API grant restoration. A later stable revision 37853 capture had HA's three permit sets populated with two members each, while Classic's three remained empty; strict Classic TCP/UDP positive observers still refused. These checkpoints are separate, and tunnel Up is not application permission.

A phase-bound read-only observation at 19:03:44.780953–.865786 UTC reproduced the environment refusal: all eleven native reads succeeded, and only ens4's `valid_life_time` and `preferred_life_time` decreased from 2187 to 2186 between address snapshots. The original byte comparison refused; exact offline replay reproduced the refusal. This truncated actual observation does not establish a complete successful `Observe` call. Earlier thirteen successful observations remain valid and did not reproduce the countdown boundary.

The narrow source fix permits only positive finite monotonic countdown within the measured read interval, bounded by the existing read deadline. Other address fields, ordering, unknown fields, assigned source, and native identity remain strict; increases, expiration, excessive decrease and forever representation changes refuse. Captured-address regression and a separate complete modeled `Observe` countdown/source-drift regression passed. The fix is locally integrated and reviewed, with deployment and fresh full native permits plus TCP/UDP packet recovery still required. No traffic-restoration, expiry completion or automatic FQDN claim follows from this local proof.

Exact key-free evidence and retained historical failures: [recovery checkpoint](../tests/gcp-s2s-local/qualification-20261010/recovery-checkpoint-13007/README.md), [expiry failure archive](../tests/gcp-s2s-local/qualification-20261010/expiry-13007-failure/README.md).

### DBCC deployment: full permissions pass, packet recovery remains open

The same-identity DBCC replacement and strict full Classic TCP/UDP permission observers passed. The actual Classic packet check still failed: target capture saw two TCP SYNs with zero exact HTTP payloads and one exact UDP request with reply timeout; self-controls passed with zero reported capture drops. Permission readback is separate from application traffic. Expiry, additional HA grants and automatic FQDN writes remain held pending fresh packet recovery.

A local ordinary Classic Apply→Maintain regression identified missing in-memory delivery identity and an initial Applying copy differing from the durable Applied/current-boot entry. Its narrow publisher repair is under independent review; no deployed repair or restored-packet claim is made here. Exact build/replacement/WG-refusal/full-proof/packet-failure evidence is retained in the [DBCC checkpoint](../tests/gcp-s2s-local/qualification-20261010/dbcc-replacement-checkpoint/README.md).

### Actual9c3 recovery and bounded expiry checkpoint

See [source-bound key-free recovery archive](../tests/gcp-s2s-local/qualification-20261010/9c3-recovery-checkpoint/README.md). Initial recovery packets passed TCP8.347ms and UDP4.690ms after strict fullpermission proof. The temporary allow→genuine deadline expiry→deny cycle passed its positive and negative phases. Normal API restoration and allocated-ID cleanup preserved the original9connections/13resources/12policies and allthree configuration views. Immediate restorednative readback had zero app tuples and refused; no restoredpacket attempt ran in that cycle. Later independent restoration passed fullTCP/UDP native proofs and packets8.752ms/4.745ms with zero drops. These are separate observations, not a continuous latency or existing-flow guarantee. Historical failures remain unchanged. Documentation commits do not change the deployed9c3 artifact identity.

### Resolver context authority and current DNS/generation checkpoint

Deployed artifact source remains `9c3ab006c13b72285f43baed1805da1af273ffa7`; later documentation commits do not change the running image. Normal authenticated resolver context version 2 preserves both Classic and HA profiles and emits resolver-only HostOrigin DNS authorization. The historical plan requiring additional ordinary HA DNS53 grants is superseded: none were created. Strict pre-context HA DNS denial and post-context exact TCP/UDP output/input-reply permissions passed; HA app A, alias CNAME and NXDOMAIN queries then passed with full native checks before and after. Private application access remains separately granted.

The historical no-EDNS Classic large-answer UDP timeout remains a failure. Google query logging established server arrival, without locating the lost reply. Separate explicit EDNS1232 qualification passed on the gateway and same-VPC target: the genuine UDP response was 67 bytes with TC set, followed by TCP returning the exact 100 A records. This is explicit diagnostic DNS fallback acceptance, not a claim that the unchanged automatic resolver uses EDNS or that the old loss cause is proven.

Normal FQDN create-v1 refused the oversized label before a returned resource ID. The corrected normal create-v2 allocated app, alias and NX resources. The bounded automatic observation ended with all three failed/timeout and no accepted generation. Its five-second broker deadline includes enqueue, delivery, resolution and response; API timeout alone does not identify a DNS socket failure. Automatic generation remains open. FQDNManaged grants remain excluded from IPsec application policy; neither ordinary IP application grants nor these DNS results qualify FQDN-only IPsec authorization.

A subsequent authorized read-only mailbox projection returned 69 requests: 57 completed and 12 expired, including completed NOERROR and NXDOMAIN responses. This proves that automatic gateway resolution and reporting sometimes occur; public timeout is not equivalent to packet timeout. Source inspection and deterministic RED/GREEN tests exposed a separate API freshness bug: validation reused the clock sampled before enqueue/await, rejecting valid responses observed more than one second later and potentially accepting answers stale at completion. Isolated candidate `86bb781e` validates against completion time and refuses cancellation or completion at/after the original deadline. It preserves the existing observed deadline, future-skew, age and identity checks. This fix is locally qualified, not yet deployed; automatic generation acceptance still requires a fresh actual observation. It does not explain every expired or resolver-unavailable request.

### API completion-clock deployment and actual automatic generation acceptance

The [accepted generation archive](../tests/gcp-s2s-local/qualification-20261011/fqdn-clock-acceptance/README.md) binds the API source0b3/tree865, installed and running executable SHA dbb82736, owned local container health and normal GET-only acceptance. App and alias had current fresh active generations at10.81.0.10; NXDOMAIN returned empty answers and the actual lowercase backend reason. All three predicates passed in one observation. Seven configured FQDN resources and their exact context remain preserved. Gateway source9c3 and image remain unchanged. Earlier all-timeout, uppercase-helper and unclassified v4 receipts are retained; this does not qualify FQDN-only IPsec application authorization.

[HA application, resolver and MTU evidence](../tests/gcp-s2s-local/qualification-20261011/ha-dns-mtu/README.md) and [DNS/generation historical evidence](../tests/gcp-s2s-local/qualification-20261011/dns-generation-history/README.md) preserve the actual packet and diagnostic outcomes. Additional ordinary DNS53 policies were not created; authenticated resolver context supplies exact host-origin resolver authority. The 1400-byte fragmented request reached the target but its reply timed out, so fragmented round-trip remains open.

## Current role and controlled MTU checkpoint — 2026-10-11

The deployed gateway remains immutable source9c3/imageDFBE/CID3bad; source0249f7cf is locally integrated, not deployed. [Role evidence](../tests/gcp-s2s-local/qualification-20261010/isolated-role-browser-20261011/README.md) binds normal organization membership and three separate Chromium contexts. Member management controls are absent; owner/admin topology and blank rotation dialogs passed. No PSK was entered or saved, and human CAS dialogs stayed untouched. A new distinct isolated CAS fixture remains source preparation only.

[Controlled MTU evidence](../tests/gcp-s2s-local/qualification-20261010/controlled-mtu-20261011/README.md) preserves actualv7 success and originalv1..v6 failures. Lowered physical1400/all-three inner1326 full guard preceded successful1400 fragmented round trips and1MiB upload/download. Final physical1460 restored with inner1326 retained, full guard and original target source/PID12359 cleanup errors empty. This proves the owned controlled fixture; it does not relabel the historical original-listener fragmented reply timeout. Checkpoint036 was pre-final completed:false;041 is actual overall success. Remaining PSK/rekey/Disable/Delete/reenable and full HA recovery gates are open.


### Classic old-peer checkpoint (source9c3 remains deployed)

Normal disabled rotation4 and Enable5 against the unchanged old cloud peer produced fixed authentication-failure notifications, strict full guard denial and actual TCP/UDP packet denial. Disable6 returned normal cleanup acknowledgment; nativev4b observed both Classic lineages absent while HA remained live. The absolute-filename failure035 is retained without observations. New cloud peer mutation, complete cutover and final restored traffic are not yet accepted. Exact receipts are in `tests/gcp-s2s-local/qualification-20261010/classic-lifecycle-old-peer-checkpoint-20261011`; candidate0249 Linux regression evidence remains local.


### Classic PSK recovery checkpoint

Normal desired7 applied, fresh allocation index20 and production-parsed native inventory passed. Independent full Classic/HA TCP/UDP guard and actual Classic/HA payload receipts052..058 passed. This closes the old-key rejection/new-key recovery slice only; restart, rekey, fault and actual isolated CAS remain separate. Deployed source stays9c3 despite later local documentation/feature commits. Exact key-free receipts are in `tests/gcp-s2s-local/qualification-20261010/classic-psk-recovery-checkpoint-20261011`.


### Isolated browser CAS accepted; historical helper failures retained

Actual first Save200 and stale second Save409 cleared the draft. Normal Delete finalized the new never-enabled fixture at revision3. GET-only reconciliation accepted exact metadata-only configuration200 and full baseline preservation after excluding only the verified owned tombstone; current inventory retains10 connections. Original UI-v1 overallfalse and readonly-v2 SDK-validation failure remain immutable. Human-owned tabs stayed untouched. Strict cutover captures059/060 failed and061 is unqualified; source-preservation proof, restart/rekey/fault remain separate.


### Strict current WG24 source qualification

Actual063 completed source-bound observation after ordinary policy inputs and the exact whole24-object renderer schema were qualified offline; earlier059/060 failures and061 unqualified observation remain unchanged. Public hash-only summaries preserve source/runtime/foreign identity without whole NFT or logs. Phased cutover, rekey and fault qualification remain open; schema qualification alone grants no teardown or native authority.


### Cutover stopped; initial strict create gate refused

Normal9c3 stop observed exit0/SAD0/no daemons and preserved retained state. First create-start refused before creation because actual six permit sets had not yet expired; the strict qualifier correctly required true emptiness. GET-only reconciliation observed old stopped/new null. Public hash/count archive preserves this checkpoint; gateway start/cutover remain unaccepted until a later complete gate.


### Current owned gateway0249 started; readiness pending

Normal create/start completed after a fresh strict gate, following the preserved initial live-permit refusal. Exact public startup measurement43345e binds source0249/imagec0ca/CIDf15e/node21074, same enrollment/boot/namespace and measured HA6/7/Classic20/SAD6. Full current guard, payload, cutover readiness, rekey and fault are not accepted by this measurement. Prior9c3 acceptance remains historical; production publication is separate.


### Fresh strict poststop gate and API reconciliation

Later fresh captureb4d7 contained six genuinely empty permit sets; unchanged full production prefix-DENY proof0098 bound its exact hash. Durable create/start receipts followed that strict gate, and normal post-cutover API baseline reconciliation passed. The earlier live-permit refusal remains unchanged. Full current native/guard/payload readiness, rekey/fault and production publication remain separate.


### 0249 current restart recovery accepted

Fresh policy-parser/currentallocation/native067 and fullcapture8d798a with all four independent Classic/HA TCP/UDP verifications passed. Actual068Classic and069HA exact payload/control/drop gates and normal API baseline preservation passed. Same-enrollment restart/cutover recovery is accepted without continuous-availability or outage-latency claims. Controlled rekey and HA one/both-path fault remain open; production publication remains separate.
