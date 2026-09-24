# EPIC — Site-to-site experience and managed VPN interoperability

Status: **Founder authorized plan publication and development start on 2026-09-24. Initial slice: customer navigation and method selection using existing WireGuard surfaces. IPsec design gates remain deferred to S2S-2.**
Date: 2026-09-24. Baseline: freshly fetched `origin/main`, `1a81f8fc`.
Planning branch: `story/site-to-site-ipsec-plan`.

## Outcome and boundaries

Customers can discover Site-to-site, connect two networks, choose Tunnex/WireGuard or an existing VPN/IPsec endpoint, and see configuration, tunnel, route and traffic evidence independently. A compatible cloud-managed VPN replaces the need for a Tunnex gateway on the remote side; a local Tunnex gateway remains required. This is network connectivity, not automatic identity discovery for users behind remote subnets.

This extends, rather than replaces, [Site Connectivity Experience](EPIC-site-connectivity-experience.md). Reuse its policy, route, validation and cloud-fabric truth contracts. Cloud provisioning remains owned by [Gateway Provisioning Lifecycle](EPIC-gateway-provisioning-lifecycle.md); overlapping subnet translation remains owned by [Site Address Translation](EPIC-site-address-translation.md). Their deferred work is not implicitly reopened.

## Verified baseline and reuse

| Area | Existing main evidence | Reuse | Missing work |
| --- | --- | --- | --- |
| Sites | `apps/api/internal/sites/`, `apps/web/src/pages/Sites.tsx` | Locations, subnet ownership and existing management | Connection-oriented projection and explicit external VPN endpoint |
| Setup | `apps/web/src/pages/NetworkSetup.tsx` | Existing gateway selection, existing-site reuse, subnet validation, review | Two-network connection journey; current wizard creates/extends a site, not a native IPsec tunnel |
| Transport | `apps/api/db/migrations/0032_sites.up.sql`; D4 in `docs/S8.1-decisions.md` | Reserved `link_transport` seam | Constraint allows only WireGuard; reservation is not implemented IPsec support |
| Gateway | `apps/node/internal/reconcile/reconcile.go` | Desired-state transport, convergence and reporting patterns | IPsec runtime, version negotiation, multi-tunnel lifecycle and independent health |
| Policy/routes | Existing site routing and node policy machinery | Reuse authoritative policies and approved ranges | Prove enforcement across IPsec/XFRM and return paths; no assumption of transport-independent kernel rules |
| Operations | Existing site-link stale and gateway status | Existing audit and status conventions | IKE/CHILD SA, rekey, tunnel-specific counters and route/traffic evidence |

No IPsec/strongSwan or BGP implementation was found in the inspected node tree. Assessment is source-based; no live packet proof was performed. Dirty local AI work remains in the original checkout.

## UI change matrix — review row by row

All rows below are proposals. No row is implemented by this paper.

| ID / screen | Customer goal / action | Current surface to reuse | WireGuard experience | IPsec experience | API / runtime dependency | Empty / error / safety behavior | Acceptance evidence | Slice |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| UI-01 Navigation | Find how to connect networks | Network section, Sites, setup entry | Network → Site-to-site | Same entry | Route and permission-aware navigation | No permission shows explanation; existing links preserved | Desktop/mobile, keyboard and deep-link preview | S2S-1 |
| UI-02 Connections list | Know what is connected and what needs attention | Site and gateway summaries | Site pair plus actual overlay path | Local site plus remote provider; tunnel count | One canonical connection projection | Empty CTA; loading/error distinct from no connections | Existing, empty, degraded and unavailable fixtures | S2S-1 |
| UI-03 Connection method | Choose intent before protocol | Existing wizard components | “Connect using Tunnex — WireGuard”; gateway at each location | “Connect an existing VPN — IPsec”; local Tunnex plus compatible remote VPN | Capability and release gating | Unsupported runtime blocks apply; no nonworking active CTA | Understandable choice and capability refusal | S2S-1/2 |
| UI-04 Provider | Select remote environment | Provider guidance patterns | Cloud/on-prem describe network location, not transport constraints | AWS, Azure, Google Cloud, Custom IPsec | Qualified provider profiles | Labels distinguish tested support, preview and unavailable | Provider/version matrix agrees with UI | S2S-2/5 |
| UI-05 Gateways/endpoints | Reuse or enroll gateways | NetworkSetup existing-site/gateway selection | Select both sites and eligible gateways | Select local gateway; enter remote endpoint and tunnel parameters | Org scope, capability, endpoint model | Prevent cross-org references; stale/offline eligibility explained | Existing-site reuse; unsupported gateway refusal | S2S-1/2 |
| UI-06 Import/configuration | Avoid hand-transcribing settings | New focused panel | No IPsec settings | Import supported provider format or enter guided fields | Validated parser, limits, secret storage/delivery | No arbitrary command execution; redact secrets in preview/logs; invalid input causes no mutation | Parser fixtures, secret leakage and cancel tests | S2S-2 |
| UI-07 Networks/access | Choose ranges and allowed traffic | Sites, routed ranges, access policies | Approved ranges and directional policy | Local/remote ranges, selectors and routing mode | Existing policy authority plus IPsec enforcement | Reject overlaps in initial scope; no implicit allow-all | Bidirectional allow and deliberate deny | S2S-1/2 |
| UI-08 Routing | Understand cloud/on-prem changes | SCX fabric guidance | Local router/cloud route next hops | Static routes initially; BGP only when qualified | Route ownership, rollback, BGP later | Clearly distinguish instructions from verified/applied state | Wrong return route shows failure despite tunnel up | S2S-2/5 |
| UI-09 Review/apply | Review exact effect before saving | Existing setup review | Sites, ranges, policies and path impact | Same plus provider, tunnel count, routing and masked auth | Idempotency, revisions and audit | Cancel has no fleet effect; stale preview refuses; partial failure recoverable | Preview matches submitted intent | S2S-1/2 |
| UI-10 Detail/health | Know whether applications can communicate | SCX health/probe conventions | Peer/link status plus path evidence | Each tunnel, active path, SA/rekey status and counters | Timestamped observations and bounded probes | Separate configured, applied, tunnel up, route ready and traffic verified; unknown stays unknown | Screenshot/state matrix plus behind-host traffic | S2S-3/4 |
| UI-11 Recovery | Resolve failures without shell commands | Gateway diagnostics/action patterns | Existing reconciliation guidance | Authentication, proposal, reachability and routing failures with next steps | Sanitized errors, safe retry and audit | Never display PSK; retry does not duplicate connections | Bad key, blocked IKE, restart and recovery cases | S2S-3 |
| UI-12 Lifecycle | Edit, disable, rotate credentials, delete | Existing confirmation patterns | Preserve existing site/range ownership | Scoped tunnel/secret withdrawal and rotation | Explicit lifecycle and resource ownership | Preview affected routes/policies; preserve shared sites/gateways and cloud resources | Post-delete traffic denied, unrelated routes retained | S2S-3 |
| UI-13 Help/export | Configure the other end | Existing documentation links | Gateway enrollment and router instructions | Provider-specific instructions and safe config export | Versioned templates, secret export rules | Never export executable unreviewed scripts; secret handling explicit | Customer follows instructions from clean setup | S2S-4/5 |

## Decision register

Planning direction is approved; implementation choices below are not silently treated as approved.

| ID | Topic | Proposed disposition | Status / implementation gate |
| --- | --- | --- | --- |
| D1 | Customer visibility | Dedicated Site-to-site entry; intent-first WireGuard/IPsec choice | Requested direction; exact navigation/labels held for UI review |
| D2 | Sites versus connections | Sites remain locations; connections reference sites and external endpoints; no duplicate site/policy authority | PROPOSED — rule before schema/API work |
| D3 | Existing WireGuard topology | Project real hub/spoke paths; a site-pair UI must not imply or create direct mesh automatically | PROPOSED — rule before connection semantics |
| D4 | IPsec engine | Evaluate strongSwan/IKEv2, isolated node-owned control interface; no custom cryptography | PROPOSED — dependency/license/packaging review before selection |
| D5 | Initial provider | AWS managed VPN first, IPv4, non-overlapping ranges, static routes, both AWS tunnels with measured failover | PROPOSED — cloud HA design before implementation |
| D6 | Data model | Connection owns multiple tunnels, revisions and observations; old site field alone is insufficient | PROPOSED — lifecycle paper and migration/rollback design required |
| D7 | Secrets | Reuse verified secret-management patterns; encrypted storage, authenticated delivery, redacted audit and bounded rotation | PROPOSED — assess existing primitives; settle read/export/revocation rules first |
| D8 | Provider support | Azure after profile qualification; Google HA VPN after BGP; Custom IPsec is not universal compatibility | PROPOSED — provider-specific wire evidence gates support labels |
| D9 | Provisioning | Customer creates remote managed VPN; Tunnex guides/imports config; cloud API automation remains separate epic | PROPOSED — no cloud credential requirement for initial flow |
| D10 | Entitlements | Reuse current WireGuard access; decide IPsec edition/licensing and dedicated permissions; enterprise unlock then opt-in | OPEN — Founder disposition needed before gating |
| D11 | Exclusions | No address translation, policy-based VPN, IPv6, certificates or arbitrary hardware compatibility in initial slice | PROPOSED — explicitly revisit if a target provider requires any excluded capability |
| D12 | Existing epic coordination | Reuse SCX wizard/health contracts; do not change its deferred roadmap or gateway provisioning scope | PROPOSED — map ownership before implementation |

## Story sequence and proof ladder

| Story | Deliverable | Depends on | Required exit evidence |
| --- | --- | --- | --- |
| S2S-0 | Decision paper, API call-site census, connection/tunnel/secret state model, review dispositions | D1–D12 | Each fork explicitly locked/rejected/deferred; regression and failure matrix defined before code |
| S2S-1 | Local interactive UI preview and existing WireGuard connection visibility | D1–D3 | Empty/loading/error/denied/long-name/mobile states; visual review; existing topology accurately represented |
| S2S-2 | IPsec vertical slice: schema/OpenAPI, node capability, packaging, provider input, policy integration | D4–D7, D9–D11 | Both API editions, generated types, node tests; valid/invalid config; mixed-version refusal; actual Linux IPsec wire proof |
| S2S-3 | Lifecycle, status, diagnostics, restart, key rotation and two-tunnel recovery | S2S-2 | Failure/retry/cancel/delete/redaction tests; measured rekey/reboot/tunnel-loss behavior; old secrets invalid after rotation |
| S2S-4 | AWS customer walk, docs and qualified support label | S2S-1–3 | Independent behind-host hosts at both ends; allow/deny; bad key; return-route failure; MTU traffic; both tunnel failures individually; cleanup preview |
| S2S-5 | Azure profile; BGP subsystem and Google HA VPN profile as separately qualified increments | S2S-4, D8 | Route filtering/max-prefix/withdrawal and peer isolation tests; separate live Azure and GCP evidence; no inherited AWS-only support claim |

No story skips the repository review protocol. Applicable local gates and exact-head CI are required for implementation. A unit test substitutes for, but never satisfies, live-wire acceptance. Review findings are ranked and held for disposition. Cloud test creation and teardown get exact resource plans at execution time.

## State and security questions to resolve in S2S-0

- Define draft, applying, observed, degraded, disabled, deleting and failed transitions; separate desired revision from gateway acknowledgement and observation freshness.
- Define resource ownership for shared routes/policies/sites; deletion must not remove shared or customer-managed cloud resources.
- Define two-tunnel route selection and failover, including return-path asymmetry; distinguish tunnel redundancy from gateway-host HA.
- Confirm nftables/XFRM ordering, source-prefix binding, default deny and protection against spoofed remote sources. A subnet must not be treated as an authenticated human.
- Specify old/new node compatibility, daemon installation and supported Linux distributions, credential rotation failure recovery and emergency withdrawal.
- Audit all mutating endpoints against visible UI call sites; document every destructive action's effects from schema and handler semantics.

## Customer completion checklist

- [ ] Customer finds Site-to-site without knowing protocol terminology.
- [ ] Existing WireGuard sites remain usable, with no duplicate site or fabricated direct link.
- [ ] IPsec flow needs no Tunnex agent on the cloud-managed remote endpoint.
- [ ] Customer sees exact ranges, access policy, routes and tunnel configuration before apply.
- [ ] Tunnel up and real traffic verified are visibly different states.
- [ ] Provider support labels match committed live evidence.
- [ ] Retry, disable, rotation and delete have explicit effects and auditable outcomes.
- [ ] Documentation includes setup, failure recovery, limitations and teardown.

## References and positioning

- [NetBird site-to-site](https://docs.netbird.io/use-cases/remote-access/site-to-site): documented routing peers at both ends.
- [Tailscale site-to-site](https://tailscale.com/docs/reference/subnet-site-to-site): documented WireGuard overlay and subnet router at each location.
- [AWS VPN](https://docs.aws.amazon.com/vpn/latest/s2svpn/how_it_works.html), [Azure VPN Gateway](https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways), [Google Cloud VPN](https://docs.cloud.google.com/network-connectivity/docs/vpn/concepts/overview): managed IPsec interoperability targets.

Competitor review on 2026-09-24 found no documented direct native IPsec termination feature in the reviewed NetBird/Tailscale guides; this is not a claim about unpublished capabilities. Potential differentiation is coexistence with managed VPNs and existing appliances. No universal compatibility, lower-cost, HA or performance claim is established by this planning document.
