# SSI-8 — Quick mode: a site link that needs no cloud return route

Epic: [EPIC-site-to-site-improvements.md](EPIC-site-to-site-improvements.md). Finding F12.

Status: **slice 1 built (artifact and gateway). Slices 2 and 3 not started.**

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
| 2 | Migration, service method with audit and convergence, capability report and guard, OpenAPI, compile-time stapling | Not started |
| 3 | The setting on the network page, with one sentence on what the LAN host will see | Not started |

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
