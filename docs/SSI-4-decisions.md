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
