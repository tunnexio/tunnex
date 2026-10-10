# EPIC — GCP site-to-site VPN

Date: 2026-10-10
Status: story plan prepared; shared foundation development started locally. GCP creation, activation and live qualification are not implemented.
Integration branch: `gcp-s2s` (main baseline `8d344e3051270565d6057fba904fcf8692afa783`).
Qualification branch: `gcp-s2s-qualification`.
Decision record: [S-GCP-S2S-decisions.md](S-GCP-S2S-decisions.md).
Parent epic: [Site-to-site IPsec](EPIC-site-to-site-ipsec.md), extending its deferred GCP interoperability scope.

## Customer outcome

An administrator connects an existing Tunnex Site to a customer-managed Google Cloud VPN, selects permitted local/remote networks, reviews the exact configuration and enables the connection. Members see permitted connection status without secrets or management actions. Tunnel establishment, route readiness and verified application traffic remain separate observations.

Use the existing Site-to-site entry point, IPsec workspace, PSK encryption/rotation, policy authority, dedicated strongSwan/VICI runtime, owned cleanup and tunnel health. Preserve AWS and WireGuard behavior.

## Supported provider contract

HA VPN + Cloud Router/BGP is the primary profile (`gcp-ha-ipv4-bgp-v1`). Classic route-based static IPv4 is a separate profile (`gcp-classic-static-ipv4-v1`), not an HA variant. The founder handoff authorizes development of both explicit profiles; the earlier routing-selection gate is removed.

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
| GCP-0 | Provider/topology compatibility contract | HA/Classic profiles; public peer/topology, selectors, inside address, ASNs, ownership/capability/rollback; cloud inventory | Owner/admin/member field/state matrix | None | No activation-critical assumptions; exact ownership and coexistence contract | In progress: project/billing/bastion verified |
| GCP-1 | Reuse current AWS/common foundations | Three-way transplant BGP/static/DNS API, FRR/IPsec and resolver foundations; preserve newer main and existing range/checker commits | Narrow common BGP/DNS components import; existing workspace retained | GCP-0 for provider adaptations | Import provenance and preservation; unchanged common-path tests reused; changed paths retested | In progress: three owners active |
| GCP-2 | Explicit profiles and disabled save | Additive schema, profiles/validator/API; encrypted PSKs; roles/tenancy/idempotency; generated contracts; mixed-version refusal | Profile/local Site/gateway/endpoints/peer fields; save disabled; masked PSKs | GCP-0, GCP-1 | Invalid/cross-org/overlapping input refused; disabled save does not apply; both API editions | Planned |
| GCP-3 | Existing form/review/setup flow | Scoped eligibility/preflight, exact profile and revision contract | GCP endpoint/BGP fields; existing review/modal/dark UI; Google instructions; stale/cancel/error states | GCP-2 | Preview equals request; no unsupported activation or secret leakage; guidance distinct from verified setup | In progress: UI owner |
| GCP-4 | Profile-aware IPsec transport | Reuse IKEv2/strongSwan/VICI/XFRM; GCP selectors/inside addressing; cardinality-aware exact ownership/refusal/cleanup for both profiles | Applied/tunnel observations and compatibility gating | GCP-2, GCP-3 | Linux wire establishment; wrong key/proposal and old-node refusal; coexistence/ownership proof | In progress: runtime owner |
| GCP-5 | Common BGP and Classic static routing | Reuse FRR sessions, exact-prefix import/export, default/subprefix refusal, max-prefix, deterministic per-prefix routing; explicit Classic route/return path | ASN/BGP fields and actual peer/routing state; Classic static guidance | GCP-4 | Actual session/route evidence; route leaks/limits/withdrawal and static return-route refusal | Planned |
| GCP-6 | Directional access authority | Shared policy/leases; expiry/revocation/spoof refusal; learned routes never grant traffic; bounded control-plane BGP | Existing allowed ranges/policy selection; explain DNS/app grants separately | GCP-5 | Real bidirectional TCP/UDP allow/deny; expired/revoked authority denies; unrelated WG/AWS unchanged | Planned |
| GCP-7 | Actual health and recovery | Fresh IPsec/BGP/routes observations; stale/unknown/degraded; individual/both tunnel loss/recovery; measure fresh and existing-flow downtime | Existing health/table/diagnostic/retry components; no UP from applied configuration | GCP-6 | Payload failure/recovery evidence and measured downtime; asymmetric paths; stale report refusal | Planned |
| GCP-8 | Lifecycle and maintenance | Restart/rekey/PSK rotation; lease expiry/recovery; Disable/Delete finalized cleanup/recreate/Enable; CAS and foreign-resource preservation | Reuse rotation/confirmations; exact cleanup effects; two-tab stale revision refusal; clear secret drafts | GCP-7 | Old key refuses; full lifecycle returns traffic; cleanup preserves unrelated resources; partial retry proof | Planned |
| GCP-9 | Private DNS over VPN | Reuse resolver/conditional forwarding/zone profiles; Cloud DNS inbound IPs; UDP/TCP53; fallback, policy expiry; LAN forwarder and private application | Existing Private DNS Resolver UX; resolver/source/zone fields; DNS and application diagnostics | GCP-6; GCP-8 for expiry/cleanup | A/CNAME/NXDOMAIN/large UDP-TC→TCP; fallback; denied DNS/expiry; resolve private app/LB then test app packets | In progress: common DNS reuse |
| GCP-10 | Integrated source-bound local/live acceptance | Provider differences/current paths; MTU/MSS/PMTUD/DF/fragmentation/lower MTU both ways; filtering/limits/routing; lifecycle/cleanup; exact source receipts | Actual role/mobile customer flows; setup/troubleshooting and measured limits; support label only after evidence | GCP-0..9 | Local tests, Linux wire, live GCP, CI and production availability recorded separately; retain owned lab for inspection | In progress: qualification preparation |

## Branch sequence

Keep `gcp-s2s` as the integration branch. The two existing branches are local and not merged into main.

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
