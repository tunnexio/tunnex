# SSI-9 — one guided flow, with preflight and a live test

Epic: [EPIC-site-to-site-improvements.md](EPIC-site-to-site-improvements.md). Findings F12 and F13.

Status: **slice 1 built; the Failover note from slice 4 built. Slices 2 and 3 and the rest of 4 not started.**

## Shape

SCX-2 (the review-first Site Connectivity wizard) is registered and not ruled. Rather than build a
second wizard beside it, SSI-9 extends the one that exists, Set up a network, so that creating the
second network is the guided link. Each slice adds one thing that flow did not say or do.

| Slice | Content | State |
| --- | --- | --- |
| 1 | The wizard offers how the new network sees other networks, defaults to the mode that needs no cloud route, and says afterwards which mode is in force and what is still to do | Built |
| 2 | Preflight before Create: a public endpoint exists in the organization; the range a local range resolves to on the gateway host (the gap SSI-7 left open); already-approved ranges that SSI-1 would now refuse | Not started |
| 3 | A bounded probe: one TCP connect from a gateway to an address inside an approved range, with its own permission (SSI-0 D6) | Not started |
| 4 | The Failover tab says when no other site can observe a same-site pair; a named health kind for a refused route; what crosses each link on the Connections page | Not started |

## Slice 1 as built

| Item | Decision |
| --- | --- |
| When it is offered | At Review, when the new network will be linked to another one and it is a new network. Extending an existing network leaves its setting alone; it is changed under Advanced. |
| Default | Gateway address (SSI-0 D5), when the chosen gateway reports it can translate. |
| Gateway cannot translate | No choice is shown. A line says servers will see the real address, the cloud must route the other ranges to the gateway, and upgrading the gateway removes that step. |
| Two writes | The network is created first, then the mode is set. If the second write fails the network is kept and reported as created, with a warning that servers will see the original address and where to change it. It is never reported as failed, and never reported as Quick. |
| After creation | Gateway address: one line, no cloud return route is needed. Original address: the two cloud steps, with the name each cloud gives the forwarding switch. First network: nothing, there is no second side. |

## Tests (slice 1)

| Test | Proves |
| --- | --- |
| `networksetup.test.tsx` › how the new network sees other networks | Default is gateway address and it is applied after creation; original address sends nothing more and lists the cloud steps; an incapable gateway is offered no choice and told what that costs; a failed second write keeps the network and tells the truth; the first network is offered nothing. |

## Slice 4, Failover note, as built

| Item | Decision |
| --- | --- |
| Rule | A hub is observable when its own network has an approved range and at least one other network has an active gateway. Gateways of the same network do not peer, so they never count. |
| What is shown | On the Failover tab, when there is more than one hub and any is unobservable: "Automatic failover cannot trigger yet" (all of them) or which hubs cannot be detected failing (some), why, and what to add. |
| What it does not claim | That a gateway **is** observing now. The Handshake column says that. This says only whether anyone could. |
| Source | The topology the page already loads. No API change. |

| Test | Proves |
| --- | --- |
| `hubsetview.test.ts` › `unobservedHubs` | A same-network pair alone is unobserved; one gateway in another network satisfies it; a network with no active gateway does not; a hub with no approved range or bound to no network is unobserved; hubs in different networks are judged separately. |

## Why the firewall check is not in slice 2 yet

The walk found that the initiating side's gateway firewall has to admit the server's traffic. A
preflight cannot see a cloud firewall from the gateway: the packets it would look for never arrive.
Only a probe sent **from** the server side, or a cloud connector (SCX-3), can tell. Until slice 3
ships the probe, the wizard and the network page name the requirement in words.
