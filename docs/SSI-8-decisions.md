# SSI-8 — Quick mode: a site link that needs no cloud return route

Epic: [EPIC-site-to-site-improvements.md](EPIC-site-to-site-improvements.md). Finding F12.

Status: **built: artifact and gateway, control plane, dashboard.** The guided flow that offers it for new links is SSI-9; the wire proof is SSI-10.

## What is wrong

A site link preserves the remote source address. The LAN host therefore answers to an address its
own network cannot route. Before any traffic flows the operator must, in each cloud, add a route
for the other site's range to the gateway and disable source/destination checking. The dashboard
mentions this only in a collapsed section; the wizard does not mention it at all.

Device traffic does not have this problem: the gateway already masquerades the device pool as it
leaves the LAN interface.

## Decisions

| Item | Decision |
| --- | --- |
| Setting | Per site, `lan_egress`: `preserve_source` (today's behaviour) or `gateway_address`. |
| What `gateway_address` does | On that site's gateways, traffic sourced from a **remote site** range is masqueraded as it leaves a non-tunnel interface. The LAN host sees the gateway's own LAN address and answers to it. |
| Policy and audit | Unchanged. The forward chain runs before the translation, so every gateway matches and records the original source. Only the LAN host sees the gateway. |
| Transit | Never translated. The rule is scoped `oifname != <tunnel set>`, like the device pool's masquerade, so a hub forwards spoke-to-spoke traffic with its source intact. |
| Scope | Per site and per direction: each site decides how its own LAN sees remote traffic. A link can be Quick on one side and preserve-source on the other. |
| Artifact | `site_lan_masquerade`, a boolean on the gateway's compiled artifact. Out-of-hash plumbing, like `pool_cidr`. |
| Version | Content-derived v15. An agent that cannot render the translation would forward un-translated traffic the LAN cannot answer while the link reports green, so it must refuse the artifact. A site left on `preserve_source` carries no flag and keeps its version and hash. |
| Existing invariant | `TestSiteToSiteNotMasqueraded` pins "site traffic is never translated". It still holds for every site that has not chosen `gateway_address`; the new behaviour is opt-in and has its own tests. |
| Default (SSI-0 D5) | `preserve_source` for every existing site. `gateway_address` is offered by the guided flow (SSI-9) for new links, and only when every gateway of the site can render it. |
| Guard on enabling | The API refuses `gateway_address` for a site with a gateway that does not report the capability, instead of letting that gateway refuse its artifact and deny everything. |

## What the operator gives up

With `gateway_address` the LAN host cannot tell which remote host connected: its own logs and
host firewall see the gateway. The identity is in Access Events and the gateway's flow log. An
operator who needs the original address on the host keeps `preserve_source` and adds the cloud
routes; SSI-9 shows the exact steps for that mode.

## Slices

| Slice | Content | State |
| --- | --- | --- |
| 1 | Artifact field, version rule, gateway render, tests | Built |
| 2 | Migration `0235`, `SetLANEgress` with audit and convergence, capability guard, `PUT /sites/{siteId}/lan-egress`, compile-time stapling | Built |
| 3 | The setting on the network page, under Advanced | Built |

## Tests (slice 1)

| Test | Proves |
| --- | --- |
| `egress.TestSiteLANMasqueradeIsOptIn` | No flag: the ruleset is byte-identical to before. Flag: one rule per distinct remote range, in canonical form, and nothing else changes. |
| `egress.TestSiteLANMasqueradeNeverTranslatesTransit` | Every rule is scoped away from the tunnel set. |
| `egress.TestSiteLANMasqueradeNeedsRoutes` | The flag alone renders nothing. |
| `policyspec.TestSiteLANMasqueradeIsContentDerived` | v15 with the flag, v5 without, and the hash changes on toggle. |
| `policyspec.TestNewContentRaisesRequiredVersion`, `TestNMinusOneAgentsCanStillApply` | The new content raises the version; the zero-config artifact is still applicable by an N-1 agent. |

`nodepolicy.TestStaticCNAMECompletionWireAndHash` asserted `MaxSupportedVersion != 14` as a
capability check. It now asserts a floor (`< 14`), like the v13 check beside it.

Wire proof: SSI-10, a real LAN host answering through a gateway with no cloud return route.

## Slice 2 as built

| Item | Decision |
| --- | --- |
| Column | `sites.lan_egress`, `NOT NULL DEFAULT 'preserve_source'`, checked. Every existing site keeps today's behaviour. |
| Capability | No new report was needed: agents already report `max_policy_version`. `gateway_address` is refused with `gateway_upgrade_required`, naming the gateway, while any active gateway of the site reports less than 15. A gateway that has reported nothing counts as "cannot". |
| Returning to `preserve_source` | Always allowed, whatever the gateways report. |
| Audit | `site.lan_egress_changed` with `from` and `to`, in the same transaction. A repeat of the current value writes nothing. |
| Convergence | The handler goes through the SSI-6 seam and is in its census, so the gateways are told at once. |
| Stapling | The flag rides with the remote routes in `finalizeSiteArtifact`, for both the enforcing and the mesh artifact. A site with nothing remote to translate carries no flag and no version raise. |
| Response shape | `Site.lan_egress` is a required field of the served site. |

## Slice 3 as built

| Item | Decision |
| --- | --- |
| Where | Network → Advanced → "Traffic from other networks", above "Advanced cloud routing". |
| Wording | Each option says what servers on the network will see and what the operator must do: "Gateway address … No cloud return route is needed." and "Original address … Your cloud must route the other networks' ranges to this gateway and allow it to forward." One line above both: access rules match the remote machine's real address either way. |
| Saving | Explicit Save. A radio that applied itself would turn an exploratory click into a production change. |
| What "current" means | The value the server last confirmed, not the last click; a refusal leaves it where it was and shows the server's reason. |
| Read-only | Without site management access the radios are disabled and there is no Save. |
| Styling | Existing disclosure, context and secondary-text classes. No new colour. |

## Tests (slices 2 and 3)

| Test | Proves |
| --- | --- |
| `sites.TestSetLANEgress` | Unknown mode and cross-organization refused; unreported and older gateways refused and not audited; capable gateway accepted; repeat is a no-op; audit records old → new; return to `preserve_source` always allowed. |
| `nodes.TestArtifactCarriesSiteLANMasquerade` | The opted-in site's gateway carries the flag at v15, in enforcing and mesh; the other site's artifact keeps its version and hash; a single-site gateway carries nothing. |
| `http.TestEverySiteTopologyMutationConverges` | The new handler is in the convergence census. |
| `sitelanegress.test.tsx` | Applied mode shown; nothing sent on click; Save sends the choice; a refusal shows the server's reason and keeps "current" on the confirmed value; read-only without permission. |

Seen on the local stack on 2026-11-20: enabling on a network whose demo gateways report no
capability returns `gateway_upgrade_required` naming the gateway; after marking them capable in the
local database the change is accepted, audited `preserve_source → gateway_address`, and the page
shows "Gateway address · current". No traffic was sent: the demo gateways are fixtures.
