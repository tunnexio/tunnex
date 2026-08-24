# S20 — Network and administration console workspace

**Status:** commit-one decision paper. Gateway slice only.  
**Branch:** `story/S20-network-admin-console-workspace`  
**Base:** `9393c533ffa18eb9ab9d5b5d8bbff2f6c1e3985d` (`origin/main`, 2026-08-24).

S20 proceeds one founder-reviewed screen at a time: **Gateways**, then Sites, Kubernetes,
Users & Roles, and Org Settings. This paper authorizes only the Gateway slice. No Sites
product change begins before the Gateway live review is accepted.

## D1 — Product and authorization model

Tunnex ships one binary. The product plans are Community, Trial, Starter, Growth, and
Scale. Gateway enrollment ceilings are deployment-wide and are returned by
`GET /api/v1/license`: Community 1, Trial 2, Starter 5, Growth 20, Scale unlimited
(`gateway_ceiling: null`). The web must render the returned `gateway_ceiling` and
`gateways_in_use`; it must not copy the tier matrix into React. A deployment already
over a reduced ceiling keeps every existing gateway running. The ceiling is checked only
when a new gateway enrolls.

Authorization order remains authentication → organization membership → RBAC → named
entitlement → organization opt-in → service work. Gateway base inventory and lifecycle
are Community capabilities. No Gateway UI or current contract may use Open/Enterprise
edition or build-selection language.

## D2 — Operator jobs and information architecture

The Gateway index is an operator inventory, not a collection of permanent forms. It must
answer:

- Which gateways are healthy, stale, degraded, or revoked, and what source/freshness
  supports that claim?
- Which site is each gateway bound to, which agent version is running, and what egress
  capability has actually been reported?
- Is a new enrollment allowed by RBAC and the deployment ceiling?
- What must move before a gateway can be revoked, and which device configurations need
  re-import afterward?
- Which safe lifecycle actions are available for one selected gateway?

Target routes:

- `/gateways` — compact searchable/sortable operational inventory with URL-backed `q`,
  `health`, `sort`, and `dir`; one header-level **Enroll gateway** action.
- `/gateways/:gatewayId` — stable detail workspace derived from the authoritative node
  list until a single-node read exists. Tabs are URL-backed as `tab=overview|health|lifecycle`.
  Browser Back/Forward restores list query and detail-tab state.

The detail route is honest about its source: a missing ID after a successful list read is
Not Found; a failed list remains an operational error, never an empty/not-found claim.
The index does not fabricate peer counts, cloud, region, or runtime facts.

## D3 — Current implementation and absence census

Current route and callers on merged main:

| Surface | Current implementation | Read/call |
|---|---|---|
| `/gateways` | `apps/web/src/pages/Gateways.tsx` | organizations, nodes, devices, sites, licence |
| enrollment ceremony | `apps/web/src/components/Gateways.tsx` | meta, optional admin gateway endpoint, join token |
| courtesy site label | Gateway page joins `Node.site_id` to Sites | list Sites |
| health/freshness | `apps/web/src/lib/gatewaysview.ts` | fields on list Nodes |
| HA hub priority | Sites page | set hub priority; remains Sites-owned in this slice |
| cascade restore | legacy Gateway component list only | hidden when `/gateways` passes `renderList=false`; missing active Gateway caller |

The merged page exposes rename, transfer, revoke, delete, and token issuance, but it
mixes inventory, confirmations, enrollment, OpenVPN, and deployment teaching in a dense
two-column page. Actions are embedded in rows; there is no stable selected-Gateway URL.
The DataTable owns local search/sort state, so Back/Forward cannot restore an operator's
position. The ceiling notice compares an organization list length to a deployment
ceiling instead of using the deployment-wide `gateways_in_use` returned by the licence
API. Permission-ineligible controls are not consistently absent.

Unavailable current contracts, explicitly deferred rather than simulated:

- S19 shared opaque `enrollment_id` and authenticated enrollment-status read. Token
  issuance proves only **token issued**; it never proves enrolled, connected, or ready.
- A single-Gateway detail read.
- Server-side keyset search/filter/sort for large Gateway fleets.
- A truthful actual WireGuard peer population/count. Device rows alone are not peers;
  site-link peers also exist.
- Cloud/region inventory and authoritative egress configuration beyond reported
  `egress_mode`.
- Safe endpoint edit (`provisioned_endpoint`/staleness contract remains absent).
- A bounded server-owned per-Gateway affected-device preview. The current screen may
  derive active+pending homing from one bounded organization device read, must mark a
  failed read unknown, and the server refusal remains authoritative.

## D4 — Complete Gateway operation/caller census

The inventory is matched by operation, method, and exact path.

| operationId | method + path | RBAC | success | active rendered owner for S20 |
|---|---|---|---|---|
| `updateGatewayEndpoint` | `PUT /api/v1/admin/gateway-endpoint` | verified deployment admin (`org:update` or CP admin) | 200 configured URL | enrollment progressive-disclosure editor |
| `listNodes` | `GET /api/v1/organizations/{orgId}/nodes` | `org:view` | 200 Node array | index/detail loader |
| `issueJoinToken` | `POST /api/v1/organizations/{orgId}/nodes/join-token` | `org:update` | 201 one-time token | Enroll gateway staged modal |
| `updateNode` | `PATCH /api/v1/organizations/{orgId}/nodes/{nodeId}` | `org:update` | 200 Node | detail Overview rename |
| `transferNodeDevices` | `POST /api/v1/organizations/{orgId}/nodes/{nodeId}/transfer-devices` | `device:transfer` | 200 exact moved/reissue result | detail Lifecycle, before revoke |
| `revokeNode` | `POST /api/v1/organizations/{orgId}/nodes/{nodeId}/revoke` | `org:update` | 204 | detail Lifecycle after authoritative zero-homed result |
| `deleteNode` | `DELETE /api/v1/organizations/{orgId}/nodes/{nodeId}` | `org:update` | 204 | detail Lifecycle, revoked only |
| `restoreNodeDevices` | `POST /api/v1/organizations/{orgId}/nodes/{nodeId}/restore-devices` | `device:restore` | 200 exact restored/readdressed result | detail Lifecycle recovery |
| `setHubPriority` | `PUT /api/v1/organizations/{orgId}/nodes/{nodeId}/hub-priority` | `site:manage` | 204 | Sites topology workspace; contextual link only here |
| `enrollAgent` | `POST /api/v1/agent/enroll` | join token credential; public protocol route | 200 certificate/CA | node agent only; intentionally not browser-called |

Deployment-wide `PUT /api/v1/admin/gateway-endpoint` is not organization-scoped. It
remains its existing authorized configuration surface and is not moved into an org
detail route, but it is included in the exact method/path caller census because it is a
browser mutation required by Gateway enrollment.

S20 must test that unauthorized controls are absent. Backend authorization remains the
enforcement boundary; the generated web RBAC policy is the display boundary.

## D5 — Destructive effects and recovery

| action | server/database effect | required warning | recovery/evidence |
|---|---|---|---|
| Transfer devices | Same-org active+pending device rows move to the chosen live node; addresses remain; site policy scope may change; one `node.devices_transferred` audit names source, target, count. | Exact bounded affected count when known; cross-site policy consequence; response's exact `needs_reissue` count. | Abandoned state is safe: old Gateway remains live. Move back through the same operation if needed; re-import marked configs. |
| Revoke Gateway | Transaction locks/checks homed devices, refuses `devices_still_homed`; marks node revoked, sweeps residual device/OVPN credentials, emits `node.revoked`; hub reconciliation and CRL rebuild occur after commit. A revoked Gateway never becomes active again. | Permanent credential refusal; no un-revoke; action available only after the bounded read says zero, while server refusal stays authoritative. | Re-enroll a replacement. Cascade-restored devices require the explicit restore operation. Audit Log is the evidence. |
| Restore cascaded devices | Restores only cascade-revoked devices onto a live replacement; deliberate revocations stay revoked; address reclamation can fail and require re-import. | Exact source/replacement and that readdressed devices require new configs. | Response reports restored/readdressed counts; repeat may truthfully restore zero; Audit Log/Devices provide evidence. |
| Delete revoked Gateway | Soft safety predicate requires revoked. Deletes node row; related node telemetry/server cert rows cascade; consumed join-token reference is deliberately cleaned so a held token stops working. `node.deleted` audit is written first with name/endpoint. | Permanent row removal and one-time token invalidation; no recovery. | No recovery. Audit event preserves identity. |

Rename is non-destructive label-only (`node.renamed`, old/new names). Token issuance is
credential-creating and secret-sensitive: display the enrollment command exactly once,
never persist it in browser storage, logs, screenshots, or reports, and dismissing it is
irreversible. A new token is the only recovery.

## D6 — Target states, status, responsive and keyboard behavior

Status is layered:

- lifecycle: active or revoked from `Node.status`;
- connectivity freshness: `last_seen_at`, with never-seen and stale explicit;
- policy/route health: `policy_degraded` plus `policy_degraded_kind`;
- OpenVPN health: separate axis from `ovpn_health`;
- egress: server-reported `egress_mode`, otherwise Checking—not false Disabled.

Required states are loading, populated, genuinely empty, durable API error with Retry,
partial courtesy-data failure (site name unavailable without blanking the fleet), stale,
never connected, revoked, permission denied, and ceiling reached/over-ceiling. Loading
must not render zero counts or empty inventory. Unknown destructive impact must never be
coerced to zero.

At wide desktop the inventory/detail layout may use two columns; at narrower desktop and
tablet it stacks without document-level horizontal overflow. Tables scroll only inside
their bounded container. Header actions wrap and remain visible. Every modal traps and
returns focus through the shared `Modal`; Escape cancels; Enter never confirms a
destructive action implicitly. Row selection and buttons have accessible names, and
status meaning is carried by text rather than color alone.

## D7 — Gateway slice acceptance and explicit boundaries

- Index and stable detail URLs load against current APIs.
- URL query/tab state survives reload and Back/Forward.
- Inventory has one primary Enroll action; no permanent enrollment form dominates it.
- Detail Overview/Health/Lifecycle expose every browser-owned mutation exactly once.
- Permission-denied controls are absent; failures remain errors; zero is shown only from
  successful authoritative data.
- Ceiling copy uses the API's deployment-wide `gateways_in_use` and `gateway_ceiling`;
  `null` means unlimited and existing over-ceiling fleets remain visible/running.
- Token issuance stops at “token issued / waiting for enrollment”; no completion claim.
- Destructive confirmations and post-action recovery match D5.
- Focused route, URL-state, permission, mutation reachability, error/empty/stale, and
  destructive-impact tests pass before disposable live review.

Sites, Kubernetes, Users & Roles, and Org Settings are explicitly outside this slice.
S19's opaque enrollment-status contract, truthful Site-to-Site dataplane readiness, and
the larger Gateway query/detail wire contracts remain named deferrals, not React mocks.

## D20 — Founder parity correction: deployment Gateway control URL

S20 is a UX redesign, not permission to strand an existing capability. The pre-S20
Gateway surface was the only rendered owner of the deployment-wide Gateway control
endpoint:

- `GET /api/v1/admin/gateway-endpoint` reads the configured raw mTLS URL;
- `PUT /api/v1/admin/gateway-endpoint` validates and saves it for deployment admins.

The first S20 enrollment composition hid that surface with
`showGatewayEndpointSettings={false}`. The optional **Public endpoint** beside a Gateway
name is the WireGuard `ip:port` peers dial; it is not a substitute for the control-plane
DNS/URL that node agents reach on port 8443.

**Ruled:** the S20 enrollment flow retains the existing admin GET/PUT contract,
permission behavior, validation, and save-before-command wiring. Authorized deployment
admins see **Gateway control URL (DNS hostname)** before token issuance. It remains a
deployment value: it is neither organization-scoped nor added to the join-token body.
The saved authoritative URL feeds `TUNNEX_AGENT_URL` in the one-time command. A caller
for whom the admin read is refused sees no field and cannot reach the PUT. The separate
optional WireGuard Public endpoint remains unchanged.

**Founder progressive-disclosure correction:** this deployment setting is not a field
that operators must review or re-save for each Gateway. When it is configured, enrollment
shows only `Control endpoint: <hostname> · Configured`; an authorized deployment admin can
explicitly choose **Change** to reveal the existing editor. When it is unconfigured, the
editor is expanded and a successful save is required before token issuance. Restricted
operators never receive the editor or PUT affordance; they may enroll only when the public
metadata confirms that a deployment admin has already configured the endpoint. Loading,
read failure with Retry, and authorization refusal remain distinct. The command always
derives `TUNNEX_AGENT_URL` from the persisted setting, while **Public endpoint** remains an
independent, optional per-Gateway WireGuard address.

**Founder parity review — state coverage and management reachability:** Gateway egress
is rendered only from the server-owned `Node.egress_mode` projection. The disposable
fixture supplies typed capability-report inputs for dual-stack and IPv4-only Gateways
and retains an unreported Gateway for Checking; no React fixture or inference fills the
field. The index keeps Gateway names linked and adds an explicit per-row **Open details**
affordance so Overview rename and Lifecycle transfer/revoke/restore/delete operations
are discoverable. Those mutations remain exclusively in the stable detail workspace;
their RBAC, lifecycle predicates, confirmation, impact, audit, and recovery behavior are
not duplicated in the inventory.

**Final Gateway audit dispositions:** the founder approved all seven audit findings for
the Gateway slice. The inventory and detail loader withdraw prior-organization facts and
permissions synchronously on organization change, and enrollment query state is removed
instead of reopening against the next organization. The deployment endpoint refusal uses
the handler's `gateway_endpoint_admin_required` contract. Mutation failures remain inside
their open confirmation so the server refusal and retry path are visible. Transfer and
restore accept only complete, non-negative integer impact responses; an incomplete body
is a contract error and never becomes a fabricated zero. The disposable egress seed
explicitly removes report keys from the Checking Gateway, making reseed deterministic.
The mutation reachability guard matches HTTP method plus exact path for endpoint save,
token issuance, rename, transfer, revoke, restore, and delete. Finally, S20 uses the
existing `bg-surface-inset` semantic token for the inventory toolbar; the nonexistent
`bg-surface-raised` utility is not added to or exempted from the color-token guard.

**Founder state-truthfulness correction:** lifecycle and observed connectivity remain
separate. An active Node without `last_seen_at` is **awaiting first connection**, not
healthy, and is excluded from the Healthy filter; the same operational state appears in
the detail header. Egress is also lifecycle-aware without changing the API: a revoked
Node with a known report is labeled **Last reported**, while a revoked Node without one
is **Not reported before revocation**, never Checking. Rows named `mcp-agent-*` remain
visible because they are real Node rows and deployment Gateway usage is Node-based.
Separating agent runtimes from Gateways requires an explicit backend classification and
counting contract; S20 does not invent a React-only filter or alter licence usage.
