# Console Navigation and Route Ownership Map

**Status:** target IA; current routes are verified in `apps/web/src/App.tsx`.

## Global shell

`AppShell` already groups destinations as Overview; Network; Access; Observe; Settings and provides organization switching, command palette, responsive/collapsible navigation, health identity, and outlet rendering. Retain it and add breadcrumb support plus shell-level offline/error presentation.

| Group | Current routes | Target owner and route direction |
|---|---|---|
| Overview | `/dashboard` | deployment/org posture and prioritized work only; link out for all configuration. |
| Network | `/gateways`, `/sites`, `/routed-ranges`, `/kubernetes`, `/agents` | Move `/agents` into its own first-class **AI Agents** group; Network remains topology and data-plane infrastructure. |
| Access | `/access`, `/devices`, `/users` | Policy, devices, people/roles. Remove agent lifecycle/JIT/template editors; retain contextual links to the owning agent workspace. |
| AI Agents | `/agents` | New top-level group: inventory, agent details, runtime, MCP, JIT, groups/templates, activity, Add Agent. |
| Observe | `/access-events`, `/audit` | immutable evidence and investigation; no configuration. |
| Settings | `/settings` | organization/deployment defaults and personal security; never entity-specific configuration. |

## Target nested routes

| Domain | Index | Detail/workspace |
|---|---|---|
| Gateways | `/gateways` | `/gateways/:gatewayId?tab=overview|network|lifecycle|activity` |
| Sites | `/sites` | `/sites/:siteId?tab=overview|subnets|dns|gateways|activity` |
| Routed ranges | `/routed-ranges` | remains an org-wide index until a range has a stable resource identity; link to its site. |
| Kubernetes | `/kubernetes` | `/kubernetes/:clusterId?tab=overview|connector|services|activity`; service row anchors retain cluster context. |
| AI Agents | `/agents` | `/agents/:agentId?tab=overview|runtime|mcp|access|activity`; group/template subroutes stay under `/agents`. |
| Devices | `/devices` | `/devices/:deviceId?tab=overview|configuration|access-posture|activity` |
| Access | `/access?tab=rules|subjects-resources|device-controls` | rules/groups/resources get dedicated routes only after the first two detail implementations prove the same need. |
| Users | `/users` | `/users/:userId?tab=overview|roles|devices|security|activity` (held pending user detail API shape). |
| Settings | `/settings?section=organization|network|authentication|directory|features|licence|danger` | retain existing rail, URL-back its selected section. |

## Auth and no-org routes

Current public/auth routes are `/login`, `/signup`, `/forgot-password`, `/reset-password`, `/accept-invite`, `/verify-email`; authenticated pre-shell routes are `/create-org`, `/verify-pending`, `/change-password`, `/enroll-mfa`, `/cli-auth`, `/cli-device`. They remain outside `AppShell` by design. Their target experience is specified in the section audit.

## Ownership hand-offs

- Gateway rows link to the selected Site, routed ranges, Devices homed there, and Audit—never duplicate their editors.
- Agent Access tab owns JIT requests, templates, and group membership; Access Policies shows read-only provenance/context links.
- Device detail links to owner, gateway, policy result, posture evidence, and exports; no gateway configuration is embedded.
- Audit is the canonical historical evidence; success surfaces link to it with action/entity filters.
