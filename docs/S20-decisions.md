# S20 — Network and administration console workspace

**Status:** Gateway slice committed; Sites HA topology layout is the first implementation slice.

**Branch:** `story/S20-network-admin-console-workspace`  
**Base:** `9393c533ffa18eb9ab9d5b5d8bbff2f6c1e3985d` (`origin/main`, 2026-08-24).

S20 proceeds one founder-reviewed screen at a time: **Gateways**, then Sites, Kubernetes,
Users & Roles, and Org Settings. Gateway live review is accepted. This amendment records
the Sites contract and safety decisions before the first narrow HA topology layout change;
the remaining Sites workspace remains decision-first.

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

## D21 — Sites slice: current contract, ownership, and information architecture

Sites is now authorized for decision-first work only. It builds on merged S8.1–S8.6 and
S14.5; it does not rewrite their history or start Kubernetes, Users & Roles, or broader
Settings work.

The existing `/sites` screen is a single local-selection workspace. It reads the current
organization's Sites, Nodes, Hub Set, and then makes one `listSiteSubnets` request per
Site; managers also cause one `listSiteDNSForwards` request per Site. It renders the
network map, DNS forwarding, pending-ranges queue, hub pinning, an index, and the selected
Site's permanent forms together. Its selection is not URL-backed. The N+1 enrichment is
not silently accepted as the future scalable contract.

The Sites operator must answer: which Sites exist; which active Gateways are bound; which
ranges are pending or approved; whether topology is only control-plane configured or has
an observed handshake; which DNS forwarding applies; what will be removed before a
destructive action; and where to recover after a refusal.

The target ownership and routes are:

- `/sites` is a compact operational index with one primary **Add site** action, a URL-backed
  bounded local `q`, lifecycle/range-state filter, and sort direction. It may offer the
  existing composite **Route a LAN** action as a secondary action only to authorized users
  with a currently unbound active Gateway. It is not an enrollment-completion claim.
- `/sites/:siteId` is the stable detail workspace. Its URL-backed tabs are
  `overview`, `ranges`, `dns`, and `activity`. Overview owns existing-Gateway binding and
  topology context; Ranges owns advertise, pending approval, and removal; DNS owns
  forwarding; Activity links to filtered Access Events/Audit Log until a site activity
  read exists. The destructive Site delete action is in detail only.
- Hub priority remains a Sites topology operation, but is displayed against the selected
  Gateway/site context rather than as a permanent unrelated panel. Gateway lifecycle stays
  in `/gateways/:gatewayId`.

Current APIs do not provide a server-side Sites index query envelope, a single-site detail
projection, a bounded all-Sites range/DNS projection, a Site activity feed, or keyset
pagination. S20 Sites must use only the currently bounded organization list and must not
promise numbered pages or exact totals beyond loaded data. **S20.1 — Sites query/detail
projection** is a named follow-up for a keyset list, bulk range/DNS summary, and detail
read; no browser N+1 is to be introduced or expanded while that contract is absent.

## D22 — Sites read/mutation caller census and authorization

All base Site capabilities are Community capabilities in the one-binary licence model.
No Site operation may use `meta.edition`, `isEnterprise`, build tags, or an inferred plan
matrix. Authentication and organization membership precede `org:view`/`site:manage` RBAC;
there is no Site-specific named feature or organization opt-in in the current contract.

| operationId | method + path | current permission / success | current rendered caller | S20 active owner |
|---|---|---|---|---|
| `listSites` | `GET /api/v1/organizations/{orgId}/sites` | `org:view`, 200 list | `/sites` loader | Sites index/detail loader |
| `registerSite` | `POST /api/v1/organizations/{orgId}/sites` | `site:manage`, 201 Site | `RegisterSiteModal` | index Add Site flow |
| `routeLAN` | `POST /api/v1/organizations/{orgId}/routed-lans` | `site:manage`, 201 Site or typed collision | `RouteLANModal` | index secondary flow |
| `listSiteSubnets` | `GET /api/v1/organizations/{orgId}/sites/{siteId}/subnets` | `org:view`, 200 list | `/sites` enrichment | detail Ranges |
| `addSiteSubnet` | `POST /api/v1/organizations/{orgId}/sites/{siteId}/subnets` | `site:manage`, 201 pending subnet | `AddSubnetModal` | detail Ranges |
| `listPendingSiteSubnets` | `GET /api/v1/organizations/{orgId}/site-subnets/pending` | `site:manage`, 200 list | `PendingQueue` | index/detail pending review |
| `approveSiteSubnet` | `POST /api/v1/organizations/{orgId}/site-subnets/{subnetId}/approve` | `site:manage`, 204/no-op | `PendingQueue` | detail Ranges/pending review |
| `removeSiteSubnet` | `DELETE /api/v1/organizations/{orgId}/site-subnets/{subnetId}` | `site:manage`, 204 | `RemoveSubnetConfirm` | detail Ranges |
| `bindSiteNode` | `POST /api/v1/organizations/{orgId}/sites/{siteId}/bind` | `site:manage`, 204/idempotent same-site | `BindGatewayModal` | detail Overview |
| `unbindSiteNode` | `DELETE /api/v1/organizations/{orgId}/sites/{siteId}/bind` | `site:manage`, 204 | `UnbindConfirm` | detail Overview |
| `listSiteDNSForwards` | `GET /api/v1/organizations/{orgId}/sites/{siteId}/dns-forwards` | `site:manage`, 200 list | `DNSForwardsPanel` | detail DNS |
| `setSiteDNSForward` | `POST /api/v1/organizations/{orgId}/sites/{siteId}/dns-forwards` | `site:manage`, 204 | `DNSForwardSection` | detail DNS |
| `removeSiteDNSForward` | `DELETE /api/v1/organizations/{orgId}/sites/{siteId}/dns-forwards/{domain}` | `site:manage`, 204 | `DNSForwardSection` | detail DNS |
| `getSiteReferences` | `GET /api/v1/organizations/{orgId}/sites/{siteId}` | `site:manage`, 200 exact rule/subnet counts | `DeleteSiteModal` | detail danger-zone preview |
| `deleteSite` | `DELETE /api/v1/organizations/{orgId}/sites/{siteId}` | `site:manage`, 204 | `DeleteSiteModal` | detail danger zone |
| `getHubSet` | `GET /api/v1/organizations/{orgId}/hub-set` | `org:view`, 200 persisted set | `HubSetSection` | topology context |
| `setHubPriority` | `PUT /api/v1/organizations/{orgId}/nodes/{nodeId}/hub-priority` | `site:manage`, 204 | `HubSetSection` | selected topology context |

`enrollAgent` and Gateway join-token/enrollment reads are protocol/Gateway-owned, not
Sites browser mutations. A Site bind or `routeLAN` success proves only control-plane
configuration. It must never be labeled **Connected**, **enrolled**, or **dataplane ready**
without the deferred server-owned observed-status contract.

## D23 — Sites destructive effects, truthful status, and recovery

| action | verified effect / refusal | required operator warning and post-state | recovery and evidence |
|---|---|---|---|
| Bind Gateway | The exact org-scoped node claim is atomic; binding the same Site is idempotent, a Gateway bound elsewhere refuses `node_already_bound_to_site`; hub reconciliation is best effort after the committed bind. | Name the selected Gateway and Site. Do not claim a handshake or traffic path. | Unbind the named Gateway or bind a replacement. Reload topology; audit/hub state is the evidence. |
| Unbind Gateway | Removes only the named node/site association. Bodyless legacy unbind succeeds only for a sole Gateway and otherwise refuses `multiple_gateways`; Site, ranges, and identity survive. Hub reconcile is best effort. | Identify exact selected Gateway; explain that Site routing may lose a transit candidate and no connectivity conclusion follows. | Bind an authorized active Gateway back to the Site. |
| Remove routed range | Deletes the pending or approved subnet. For an approved range, the normal full sweep withdraws it from every Gateway on next reconcile; DNS forwards whose resolver was inside the removed range are swept in the same transaction. Audit names CIDR, prior status, and swept domains. | Display exact range/status and server-known swept DNS domains when served; warn approved-range traffic can lose reachability. | Re-add then approve a replacement range; recreate swept DNS forwards if appropriate. |
| Remove DNS forward | Removes/withdraws the selected domain mapping; no ambiguous partial success. DNS set/update refuses a resolver outside an approved Site range or a domain owned by another Site. | Name domain and resolver; explain resolution withdrawal. | Set the forward again after its resolver/range is valid. |
| Delete Site | Transaction refuses active Agent Access requests and immutable Agent Policy Template references. On success it cascades Site subnets and Site-referencing policy rules and unbinds Gateway nodes; `site.deleted` audit records exact pre-delete rule/subnet counts. | Use `getSiteReferences` plus named server refusal before confirmation; explain irreversible Site record removal, cascade counts, and Gateway unbinding. | No undelete. Recreate Site, bind Gateway, re-add/approve ranges and rules. Audit preserves evidence. |
| Route a LAN | Composite register/bind/advertise/approve. A range collision returns `subnet_not_disjoint`; Site, binding, and pending advertisement can deliberately remain for safe resume. Same Site/Gateway/CIDR retry is idempotent and foreign pending ranges are preserved. | Explain that a collision is a partial, recoverable control-plane state—not a completed route. Surface exact typed overlap teaching. | Correct CIDR and resume; retain/explicitly review pending ranges rather than deleting them silently. |
| Approve range | Approval is idempotent. Disjointness collision refuses and leaves the range pending; both success and refusal are audited (refusal audit is deliberately committed separately). | State pending→approved transition; conflict remains pending and needs renumbering or roadmap subnet mapping. | Correct/remediate range then retry; approval does not prove data-plane readiness. |
| Hub priority | Changes persisted HA candidate order and can change transit selection; service audits old→new. | Identify Gateway, previous/new priority, and that it is topology policy not a connection proof. | Clear/reset priority through the same control; use hub/audit evidence. |

All destructive/mutation controls are absent for a user without `site:manage`; read-only
topology remains available through `org:view`. Loading, error, partial enrichment,
permission denied, empty, pending, ambiguous binding, revoked Gateway, and stale/never-
handshaken link states are separate. A failed subnets/DNS enrichment remains partial/error,
not zero ranges or no DNS zones.

## D24 — Setup flow and topology truth boundaries

The future S20 Sites workflow is **create/select Site A → select an existing active
Gateway → bind → declare CIDR → review/approve → repeat for Site B → create policy grant
through Access → observe topology and actual data-plane evidence**. The current UI/API
does not offer a Site-to-Site policy/grant creation operation within Sites; Access remains
the authoritative policy owner. Sites links there contextually rather than duplicating the
rule editor.

The existing `NodeLink`/Hub Set handshake information is an observed connectivity axis,
not deployment success. It may truthfully say a current handshake is observed, stale,
never reported, or unavailable. It must not turn a join token, bind, Site row, route
approval, or policy row into a **Connected**/ready claim. **S19 enrollment correlation**
remains the named shared opaque `enrollment_id`/status contract; **S20.2 Site-to-Site
readiness** remains a named server/event contract for correlating control-plane intent,
Gateway handshake, policy compilation, and actual dataplane verification. Neither is
implemented by React inference in the Sites slice.

Gateway plan ceilings remain deployment-owned values from `GET /api/v1/license`. Sites
may select currently active existing Gateways but does not hardcode tier ceilings or imply
that a token/bind changes plan usage. When a new Gateway is required, it deep-links to the
Gateway enrollment workflow, whose API reports current plan, in-use count, and ceiling.

## D25 — Sites UX, responsive behavior, and acceptance gates

Use existing `PageHeader`, `DataTable`, `Modal`, status chips, `NodeLink`, and shared
loading/error/permission primitives. Do not introduce an EntityIndex/EntityDetail mega
component. An index row and explicit **Open details** affordance lead to a stable route;
the selected detail uses tabs rather than an ever-growing page of forms. Header actions
wrap; data tables scroll only within their container; narrow widths stack detail below
the index. URL state restores query, selection, and tab with Browser Back/Forward.

Empty states explain the value and one next action. `site:manage` controls are not
disabled decorative controls for a read-only operator: they are absent, while the
permission boundary is explicit. All confirmation dialogs name actual targets, exact
server-derived impact where the current preview supplies it, and recovery. A service
error stays in the dialog with Retry; a successful mutation refetches its authoritative
read source. Keyboard behavior follows shared Modal focus/Escape rules.

Before founder review, S20 Sites must prove route/state/back behavior; every D22 mutation
has exactly one rendered owner; delete/range/DNS/unbind/route-LAN impact and recovery;
RBAC-first cross-org behavior; no fake zero from failed enrichments; no false connection
claim; and desktop/narrow table containment. S20.1, S19, and S20.2 remain explicit
deferrals, not reasons to suppress existing Site operations.

## D26 — Founder-reported HA topology layout correction

The current `meshFrom` projection collapses the served HA set to the first active
`is_site_hub` Node, and `NodeLink` has one hard-coded centre position. That is not an
honest representation when `GET /api/v1/organizations/{orgId}/hub-set` serves a primary
and one or more standbys: the primary/standby relationship is authoritative, but the
diagram does not receive or lay out all members. In the founder-reported hub-and-spoke
arrangement, central cards, labels, badges, and lines can therefore stack or become
unreadable.

**Ruled:** `meshFrom` consumes the served Hub Set member order, not a React election. It
creates one stable primary hub and one stable node for every served standby. `NodeLink`
uses a deterministic central HA layout, a collision-free outer spoke ring, and clips only
the visible SVG label while retaining the full accessible name. Edge endpoints are
shortened to the rendered node boundaries. A Site edge that would cross an unrelated HA
member is deterministically routed around the whole readable member envelope (ring,
status badge, and label), rather than removing the truthful primary-to-Site relationship
or adding an invented primary-to-standby edge. No diagram edge is added merely to make
HA look connected: observed link tone still comes only from the existing server-derived
site-link facts, and the primary/standby labels describe membership rather than live
dataplane readiness.

The disposable fixture must persist an authoritative two-member Hub Set (primary
`gw-us-east`, standby `gw-eu-west`) plus the existing bound/unbound spokes, using the
same server schema and `GET /hub-set` projection that production uses. It is idempotent
and is applied only to `tunnex-s18-review`; neither `tunnex-agents` nor a React-only mock
is touched. The fixture source writes generation `7`, but generation is controller-owned:
the disposable API was observed at `8` before reseeding and at `7` immediately after each
of two repeat reseeds. In every read the served membership/order remained primary
`gw-us-east`, standby `gw-eu-west`. Generation is therefore never a fixture/UI assertion;
the controller remains authoritative and the UI must not force it back if it advances.
Tests cover a single hub, HA hubs with spokes, long
labels/status text, narrow layout geometry, unrelated-HA edge clearance, edge/node-boundary
termination, keyboard selection, deterministic reload output, and no missing topology
member or false readiness claim.

## D27 — Founder-reported Sites topology progressive disclosure

**Decision:** the default Sites map is an organization overview, not a fleet graph. It
renders only one aggregate node per served Site and the authoritative Hub Set members.
It never renders human devices, agent devices, connectors, or a primary-to-standby
dataplane edge by default. A Site-to-hub relationship is therefore `O(number of Sites)`,
not an all-entity mesh.

### Current facts and limits

The current page reads `GET /sites`, `GET /nodes`, per-Site `GET /subnets`, and
`GET /hub-set`. `Node.site_id`, lifecycle, freshness, and differentiated health are
server-owned, so the existing `SiteCard.gateways` join can truthfully expose a Site's
gateway identity/count and worst known gateway health from that loaded Node inventory.
`meshFrom` already produces Site and Hub Set nodes only; it does not render Device rows.

However, neither `Site` nor `Node` currently carries a server-owned per-Site device
count, attention count, connector count, or a database-computed aggregate health/count
projection. Fetching all Devices merely to decorate a graph would be an unbounded client
join; treating a missing/failed list as zero would be false. The current list reads are
also not a scalable keyset aggregate contract. Those facts are therefore **not** added
to Site nodes in this slice.

### Scoped implementation direction

1. Preserve the present default Site + served-Hub-Set graph and its deterministic,
   collision-aware HA geometry. Add a compact Site search/focus control that selects and
   highlights one existing Site node; unrelated nodes/edges may de-emphasize, never
   disappear from the authoritative overview.
2. A selected Site summary shows only already-loaded Site/gateway facts. **Explore site**
   is an explicit action: it may show a bounded gateway subset only if every loaded
   gateway is represented; otherwise it shows the authoritative total that the future
   projection returns plus a link to the canonical filtered Gateway inventory. Devices
   and connectors remain filtered inventory links, never graph nodes.
3. Provide Fit/reset and a compact/list fallback. The graph itself remains capped to its
   readable Site/Hub presentation; if Site volume exceeds the future server-provided
   readable aggregate bound, the UI withholds a partial graph and directs the operator to
   the compact list.
4. The first scalable count/read shape is **S20.1 — Site topology aggregate/query
   contract**: a bounded, org-scoped Site projection with exact gateway/device/attention
   counts, worst-known aggregate state, keyset search/focus, explicit unknown/read-error
   semantics, and a bounded expanded-gateway result with `remaining_count`. It must be
   OpenAPI/API-first. No client-side Device sweep, fabricated zero, or React-only
   readiness/count is permitted before S20.1 exists.

**Current S20 implementation boundary:** the organization overview, URL-backed Site
search/focus/reset, selected-Site emphasis, compact inventory fallback, and full existing
Sites mutation workspaces are implemented from the reads above. The graph still does not
claim device/connector/attention aggregates or an expanded Gateway graph: those remain
S20.1 work until a bounded server projection exists.

### Required disposable proof for the implementation slice

The disposable `tunnex-s18-review` fixture will add at least ten active/revoked Gateways
across multiple Sites, a two-member authoritative HA Hub Set, large Device populations
represented only through server aggregate facts once S20.1 exists, and distinct
unhealthy/unknown aggregate cases. It must be idempotent and never touch
`tunnex-agents`. Regression proof must show no device/connectors node explosion, no
omitted Site/Hub member, stable focus/search/reset, a truthful `+N more`/inventory
handoff when expansion is bounded, long-label/no-overlap narrow layout, `fill="none"`
for every edge, and no claim of live dataplane readiness beyond served evidence.

## D28 — Sites full-workspace implementation checklist

This is a complete Sites UX slice, not a topology-only correction. S20.1 remains deferred,
but it does not block reorganizing every capability already supported by authoritative APIs.

| Existing operation | Active rendered caller | Impact/recovery truth |
|---|---|---|
| `POST /sites` | header **Add site** / Register Site modal | creates an empty Site; bind/advertise afterwards |
| `POST /routed-lans` | header **Route a LAN** modal | atomic register/bind/advertise/approve; server refusal is rendered verbatim |
| `POST /sites/{siteId}/subnets` | selected Site **Advertise subnet** | creates pending range; approval is separately required |
| `POST /site-subnets/{subnetId}/approve` | Pending approvals confirmation | server disjointness and policy-version impact; retry remains in the confirmation |
| `DELETE /site-subnets/{subnetId}` | selected Site remove-range confirmation | approved route withdrawal and DNS-forward dependent facts shown before mutation; re-advertise to recover |
| `POST /sites/{siteId}/bind` | selected Site **Bind gateway** | server binds selected active Gateway; unbind/rebind recovers |
| `DELETE /sites/{siteId}/bind` | selected Site unbind confirmation | routes/peers swept, Site/subnets retained; bind replacement to recover |
| `DELETE /sites/{siteId}` | typed-name selected Site delete confirmation | server Site-reference and template-destination impact shown; recovery is create/rebind/re-advertise, not restore |
| `PUT /nodes/{nodeId}/hub-priority` | HA section pin/unpin controls | served Hub Set ordering changes; clearing pin restores controller election |
| `POST /sites/{siteId}/dns-forwards` | selected Site DNS forwarding panel | resolver/domain validation is server-owned; remove to withdraw |
| `DELETE /sites/{siteId}/dns-forwards/{domain}` | selected Site DNS forwarding row | withdraws on next reconcile; re-add to recover |

The page must keep one stable selected-Site identity in the URL (`site`), URL-backed
search (`q`), and a URL-backed operational section (`section=overview|approvals|ha|dns`).
On an organization change it clears inventory, selection, permissions, modal/mutation
state, and URL selection before the next org read resolves. The inventory is authoritative;
the topology is an overview and a second selection affordance. Read-only members retain
served context but no mutation affordances. Loading, empty, retryable failure, partial
DNS read, and unavailable HA facts remain visibly distinct.

## D29 — Sites workspace layout consolidation

The Sites redesign retains the D28 callers and URL state, but does not retain a permanent
mostly-empty right rail. Overview gives the map the available width, fits the actual
rendered topology bounds into the available canvas with bounded zoom, and limits its height
so the Site inventory enters the first viewport. A compact selected-Site context strip
replaces duplicated detail actions. Pending approvals, Hub availability, and DNS forwarding
are each a single full workspace surface. HA renders Current Hub Set as a compact full-width
summary, followed by its full-width candidate/priority inventory; the longer list must not
stretch a sparse sibling column. Tables may scroll inside their own container on narrow
screens, never at the document level. The shell resets its owned scroll container on real
page/workspace-section transitions so the global header cannot cover a restored page title;
site/query selection keeps its local context. The selected Site remains the sole detailed
mutation workspace below the inventory, with destructive actions separated into a Danger
zone and no artificial minimum height.

## D30 — Route a LAN carrier eligibility

`nodes.enrolled_kind` is the authoritative enrolment declaration: `gateway` is a
Gateway-capable carrier and `agent` is not. The previous generic Node projection omitted
that fact, so the Route a LAN picker could offer AI-agent Nodes and the Sites service could
bind a crafted request to them. The Node read projection now exposes the nullable declaration
without guessing at it. Route a LAN and direct Site binding fail closed unless the Node is both
active and explicitly `gateway`; a legacy NULL declaration is not presented as eligible. The
service enforces the same check before any Site/binding mutation. Fixture Nodes explicitly
declare their real kind; no name-prefix heuristic is used.

## D31 — Sites presentation and topology interaction contract

All Sites workspaces use one compact operational grammar: a section header and one-line
purpose, a consistent table header/row rhythm, aligned trailing actions, restrained status
chips, and dividers rather than nested decorative cards. `linked/healthy`,
`attention/degraded`, `down/offline`, `pending`, `conflict`, `unknown`, and `disabled` each
have one semantic text-plus-shape treatment; colour never carries the state alone. Empty
states explain the next useful action without a large blank slab. Existing API callers,
RBAC, confirmations, URL state, and recovery copy remain unchanged.

The map search is a real combobox over the already loaded authoritative Site and Node
inventory. A Site result selects its Site; a bound Gateway selects its owning Site and
records the selected Gateway in URL state; an eligible unbound Gateway is explicitly
unbound and offers the existing Route a LAN action rather than a fabricated map position.
Search never removes topology members. Enter selects a unique/exact result, Escape closes,
and clear restores the overview. Linked edges are solid with the existing justified motion;
degraded edges are attention-coloured with a long dash; down edges use a danger short-dash;
unknown is muted dash-dot. Legend samples reuse the actual edge contract.

Map fitting measures the rendered topology bounds and container, recomputes on resize and
focus changes, retains fixed readable ring size, and withholds graph expansion rather than
presenting a partial graph. Selected Site detail uses compact labelled Gateway/range rows,
secondary disclosures for cloud/DNS guidance, one operational action group, and a compact
Danger-zone row with server-authoritative impact/recovery and right-aligned delete action.

DNS ownership is intentionally split: **DNS overview** is organization-wide inventory and
conflict visibility only; every manageable row navigates to its owning selected Site with
URL-backed DNS disclosure focus. The selected-Site disclosure remains the sole Add/Remove
caller. The overview has no mutation controls, retains the non-deterministic conflict
warning, and shows an unavailable owner rather than a broken action.

Non-Overview sections are canonical task URLs: direct/reloaded `approvals`, `ha`, and
`dns` URLs remove Site, Gateway, search, and DNS-disclosure parameters with history
replacement. Only Overview owns that local context. DNS resolver guidance never borrows
another Site's address: it names the selected Site's approved CIDR when one is already
served, otherwise it uses neutral approved-subnet guidance; it never pre-fills a value.
