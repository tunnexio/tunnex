# SSI-1 — a wrong range is refused with a reason

Epic: [EPIC-site-to-site-improvements.md](EPIC-site-to-site-improvements.md). Findings F1 and F11.

## What was wrong

A site range was checked only for overlap with ranges the organization already owned. A public range,
or a prefix covering half the address space, overlaps none of them, so it could be advertised and
approved. Once approved it is a route on every other gateway and an allowed range on every device.

## Decisions

| Item | Decision |
| --- | --- |
| Rule | A site range must lie wholly inside `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` or `100.64.0.0/10` (SSI-0 D2). |
| Where | `subnetguard.Admissible`, a static rule with no organization input, asked before the disjointness check. |
| Seams | Advertise (`AddSubnet`), the one-screen route (`RouteLAN`) and approve (`ApproveSubnet`). |
| Refusal codes | `range_not_private`, `range_too_wide`, `range_not_ipv4`, HTTP 400, with the admissible blocks in the message. |
| State after refusal | None. `RouteLAN` asks before it creates anything. This differs on purpose from an overlap refusal, which keeps site, binding and pending subnet as the resume target: an overlap can be cured from the other side, a public range cannot. |
| Legacy pending rows | A range advertised before this gate is refused at approval, audited as `site.subnet_approval_refused` with the reason, and stays pending for the operator to remove. |
| Already approved rows | Not touched. Nothing is withdrawn on upgrade. Reporting them is **deferred to SSI-9** (preflight), trigger: the guided flow lists a network's ranges. |
| Override (D1) | Not built. **Deferred to SSI-1b**, trigger: a customer needs a public destination routed through a gateway. |
| F11 | When the bind fails in a fresh `RouteLAN`, the site created for that call is removed, so a retry does not meet `site_name_taken`. |
| Reserved set | The control-plane address and gateway endpoints are public addresses in the deployments seen so far and fall outside the admissible blocks. A private endpoint inside a site range is **not** checked here; it belongs with the gateway-network check in SSI-7. |
| OpenAPI | Unchanged. The spec does not enumerate error codes for these operations; the wizard renders the API message as it does for `subnet_not_disjoint`. |

## Tests

| Test | Kind | Proves |
| --- | --- | --- |
| `subnetguard.TestAdmissible` | unit | Every class: private, shared, whole block, public, link-local, loopback, multicast, wider than a block, just outside a block, IPv6. |
| `sites.TestRouteLANRefusesInadmissibleRange` | integration | Refusal leaves no site, binding or subnet; an admissible range still works afterwards. |
| `sites.TestAddSubnetRefusesInadmissibleRange` | integration | The advertise seam refuses and stores nothing. |
| `sites.TestApproveSubnetRefusesLegacyInadmissibleRange` | integration | A legacy pending public range is refused, stays pending, and the refusal is audited once. |

Red before the fix: `Admissible` did not exist and the three integration tests fail on main.
