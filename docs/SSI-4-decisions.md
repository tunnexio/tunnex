# SSI-4 — what linking two sites opens

Epic: [EPIC-site-to-site-improvements.md](EPIC-site-to-site-improvements.md). Finding F2.

Status: **RULED 2026-11-20: option A now, option B next.** A fork surfaced before the build and was
put to the Founder with the three options below; the recommendation was chosen. SSI-4 builds A.
B is registered as **SSI-4b**, to start after SSI-8. C is rejected: it would turn enforcement on
without an opt-in.

## The fork

SSI-0 D3 was accepted as "new organizations start closed; existing ones are migrated with explicit
grants". Read against the code and `CLAUDE.md`, that design collides with a standing rule:

> Enterprise features are UNLOCK-THEN-OPT-IN, never unlock-and-enforce: org-level opt-in, default
> OFF. Unlocking makes a capability available; it never turns enforcement on.

Today a gateway whose organization has enforcement off renders the mesh: everything that arrives
through a tunnel is forwarded, and LAN → tunnel is open to every remote site range
(`apps/node/internal/egress/egress_linux.go`, `forwardRules`). The `sites` package states that
governing site traffic is the enterprise half. Closing site links by default would turn enforcement
on for a class of traffic without an opt-in, in every edition.

## Options

| | Option | What the operator sees | Cost |
| --- | --- | --- | --- |
| A | Keep the default open; make it explicit | Linking shows, before it is applied, exactly what becomes reachable in both directions, and requires an acknowledgement. The Connections page shows "open: every address, every port" on the link until a rule narrows it. No data-plane change. | Small. Honest, but a link is still open until someone acts. |
| B | Opt-in site isolation, per organization, default off | A setting "Site links follow access rules". When on, gateways forward site ↔ site traffic only for compiled grants, whatever the device enforcement mode. The guided flow (SSI-9) offers to turn it on. | Medium: an artifact field, an agent capability so a mixed fleet is not locked out, new forward rendering with goldens, and a ruling on which edition carries it. |
| C | Closed by default for new organizations, migration for existing ones | The original D3. | Largest, and contradicts the opt-in rule unless that rule is amended. |

## Recommendation

**A now, B next.** A removes the surprise at no risk and needs no ruling on editions. B gives the
safe posture to anyone who wants it without enforcing it on anyone. C only if the Founder amends the
opt-in rule for site traffic.

## Constraint that applies to B and C

A new artifact field must not reach an agent that cannot interpret it: an agent that refuses an
artifact version denies everything. The control plane therefore has to emit the gated form only to
agents that report the capability, the way `egress_nat` is reported today, and show the rest as not
yet gating.

## Built: option A

| Item | Decision |
| --- | --- |
| Where | The Review step of Set up a network, the only place a range is approved in one action. |
| What it reads | The organization's enforcement mode and the approved ranges of every other site. Pending ranges are left out: they are routed nowhere. The gateway's own site is left out: it is not a second side. |
| Enforcement off | A warning names the other networks and their ranges and says every address reaches every address, both directions, every port. Create network stays disabled until the operator ticks "I understand this link is open in both directions". |
| Enforcement on | One neutral line: nothing crosses the link until an access rule allows it. No acknowledgement. |
| First network | Nothing is shown; there is no second side. |
| Mode unreadable | Said as such, and treated like off: an acknowledgement is required. The safe mode is never guessed. |
| Other networks unlistable | Said as such, with its own acknowledgement. An unread list is not an empty one. |
| While reading | Create network is disabled until the read finishes, so a slow response cannot be used to skip the notice. |
| No API change | Three existing read endpoints. No data-plane change: the link is exactly as open as before, and now the operator is told. |
| Colour | The existing warning tone for off and unknown; the neutral secondary tone for on. No new token. |

Not built here: the same statement on the Connections page, per link. It belongs with SSI-9, which
rebuilds that page.

## Tests

| Test | Proves |
| --- | --- |
| `sitelinkview.test.ts` | The projection for off, on, unknown, no second side, and stable ordering. |
| `networksetup.test.tsx` › what the range will be linked to | Create is blocked until acknowledged when open; nothing asked when enforcing; nothing shown for the first network; an unlisted set and an unread mode are both said and both require acknowledgement; the gateway's own site is excluded. |

Seen on the local stack on 2026-11-20 with the seeded demo organization (enforcement off, three
other networks): the warning lists `ap-lan`, `eu-lan` and `us-east-dc` with their ranges and Create
network is disabled until the box is ticked.
