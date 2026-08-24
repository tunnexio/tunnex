# Tunnex Console Section Specifications

This is implementation-ready UX behavior, not approval to implement. All reads/actions use generated OpenAPI client calls; exact endpoint paths are named for mutations. Permission checks use current `rbac-policy.json`; enterprise gates use `edition.ts` only after permission resolution.

## 1. Global application shell

- **Jobs/questions:** Which organization am I operating? Where am I? Is the console/API healthy? What requires attention?
- **Target:** retain `AppShell`, `OrgSwitcher`, grouped responsive nav, command palette, `Toasts`; add breadcrumbs, shell offline banner, session-expired re-auth prompt, and global retry only for shell/bootstrap reads. No toast is the only record of a mutation.
- **Actions:** org switch uses existing organization context; sign-out `POST /api/v1/auth/logout`; navigation is role-independent except page-level gates.
- **Acceptance:** selection never silently resets; every route has a focused main landmark; collapsed/mobile nav retains all destinations; back navigation preserves context; offline prevents mutations and labels data stale.

## 2. Authentication and onboarding

- **Jobs/questions:** Can I authenticate safely? Is my email verified? Was an invitation accepted? What mandatory action blocks entry? Can the bootstrap administrator establish the first organization?
- **Current APIs/actions:** signup `POST /auth/signup`; login `POST /auth/login`; MFA start/confirm/disenroll/verify; verification/resend; password reset/request/confirm/change; invitation accept `POST /auth/invitations/accept`; first org `POST /organizations`; CLI authorization/device routes.
- **Target:** show a single explicit progress context across public pages: account credentials → verification → forced password change → MFA when policy requires → membership or CP-admin create-org. Each page has durable error, expired-token, mail-not-delivered, and safe retry states; no global navigation before `RequireOrg` admits the user.
- **RBAC/edition:** self-service auth is open; SSO endpoints/settings are enterprise; create-org requires CP admin; invitations do not grant setup authority.
- **Acceptance:** every refusal names the next valid route; browser Back does not bypass password/MFA gate; verification/reset tokens have expired/invalid states; empty-membership screen distinguishes loading/failure/true absence.

## 3. Overview dashboard

- **Jobs/questions:** What is broken, pending, stale, or unsafe right now? What is the next owned action?
- **Target IA:** priority queue first, health summary second, trend/summary last. Queue sources: gateway degradation, pending device/subnet/JIT approvals, stale agent runtime, unreconciled policy, and required setup. Links always open the owner route with a pre-applied filter.
- **Columns/cards:** severity/reason, entity, owner domain, last observed, next action. Do not repeat configuration controls.
- **States:** partial data retains healthy cards but labels unavailable feeds; unknown is not zero; empty fresh org gives ordered setup checklist.
- **Acceptance:** each actionable card deep-links; no widget claims liveness without source/freshness; dashboard mutation is limited to safe approval/shortcut actions already authorized.

## 4. Network

### Gateways

- **Job:** enrol, investigate health, place at site, transfer devices, revoke/delete safely.
- **Index:** URL filters `q,status,site,sort,dir,limit,cursor`; columns in audit document. Cursor is opaque and totals appear only when server-returned. Row link detail; overflow Rename (`PATCH /nodes/{id}`), Transfer (`POST /transfer-devices`), Revoke (`POST /revoke`), Restore (`POST /restore-devices`), Delete (`DELETE /nodes/{id}`), hub priority (`PUT /hub-priority`).
- **Detail:** Overview, Network & service, Lifecycle, Activity; health uses canonical gateway helpers and `last_seen_at`; revoked suppresses healthy badge.
- **Add flow:** name/details → prerequisites/review → issue token (`POST /nodes/join-token`) → copied install command → waiting for server-observed enrollment → connected. Enrollment correlation/status API is a held security/API decision; do not infer it from duplicate names.
- **RBAC/edition:** existing node permissions/ceiling behavior; lifecycle controls absent when unauthorized, ceiling is a successful refusal not an error.

### Sites and routed ranges

- **Job:** represent private LANs, advertised CIDRs, gateway binding, DNS forwarding, and path conflicts.
- **Actions:** register site, route LAN, subnet/DNS create/remove, bind/unbind, approve subnet, delete site using current `/sites`, `/routed-lans`, `/site-subnets` endpoints. Site detail tabs own these actions; routed ranges is read/index with source links.
- **States:** pending approval, approved, conflict/refused, reconcile pending, stale gateway report, empty topology. All editions can view topology; management remains permission/verified-email gated.
- **Acceptance:** deletion confirmation names server-provided rule/subnet effects; no route is shown as active before approval/reconcile evidence; keyboard table rows expose CIDR and source.

### Kubernetes

- **Job:** register a cluster, select its connector, expose a private Service, know reachability and policy ownership.
- **Actions:** register/deregister cluster; set connector; expose/unexpose service via current `/k8s/*` endpoints. Detail tabs own connector and services; service actions are contextual to the cluster.
- **States:** connector absent/revoked/unreachable; service pending/exposed/unexposed; partial cluster/service read; policy reference refusal. Kubernetes connectivity is core, while access grants remain Access/enterprise behavior.
- **Acceptance:** never substitute a different gateway for a selected connector; confirmation describes withdrawn VIP/DNS/service cascade; all actions link to audit.

## 5. AI Agents

- **Job:** add/enrol an agent; establish runtime/MCP identity; understand connectivity; control access; investigate activity.
- **Index:** target URL `q,lifecycle,runtime,mcp,access,gateway,sort,dir,limit,cursor`; current API lacks this query/page envelope, so the target is gated by S18's index API change. Columns name, lifecycle, gateway, runtime/connectivity, MCP inventory, policy/JIT state, last report. Primary Add Agent; rows open `/agents/:id`.
- **Detail tabs/actions:**
  - Overview: metadata/lifecycle `PATCH /agents/{id}`; credential rotation request/status.
  - Runtime: runtime setting/status and bootstrap protocol; status source is runtime report timestamps.
  - MCP: inventory, OAuth connection start, immutable tool policy replace, step-up approvals.
  - Access: JIT setting/requests; agent groups/templates/profile assignments. Access page links here, not editors.
  - Activity: workflow provenance, access events and filtered audit.
- **Add Agent flow:** choose identity/runtime/gateway → validate org/runtime prerequisites → mint bootstrap token (`POST /agents/bootstrap-token`) → one-time install/bootstrap → wait for profile/runtime report → connected. Agent bootstrap/runtime endpoints used by the installed agent remain browser-ineligible.
- **RBAC/edition:** enterprise capability; resolve permission before upsell; separate lifecycle, MCP policy, JIT approve, and template permissions.
- **Acceptance:** one clear owner for every agent setting; direct-upstream MCP boundary stays explicit; stale/unknown runtime never reads offline; template/JIT dependency refusal remains visible.

## 6. Access

### Access Policies

- **Job:** answer who may reach what, why, for how long, and whether enforcement converged.
- **Target tabs:** Rules; Subjects & resources; Device controls. Actions call current group/resource/policy/zero-trust/health-check/device-approval endpoints. Primary action changes per tab only.
- **States:** enforcement off/on, rule enabled/disabled/expiring, managed/immutable, propagation pending/failed, permission/edition distinction. Rules table columns are subject, destination, protocol/ports, mode, expiry, enabled, source, changed.
- **Acceptance:** disabling/deleting states exact access impact and audit action; agent-managed rules link to agent provenance rather than expose unsafe generic edits.

### Devices

- **Job:** issue/export a device profile, assess owner/gateway/posture/config freshness, approve/reject, revoke/remove.
- **Actions:** create/export/revoke/remove/approve/reject via existing device endpoints. `PATCH .../mode` has no UI caller and remains held, not silently added. Detail route tabs in route map.
- **States:** pending/active/revoked/suspended; online is handshake-derived; posture unknown/stale; config needs re-export; OpenVPN profile status. Permissions/enterprise gates use existing server behavior.
- **Acceptance:** never default among multiple eligible gateways; export is guarded by exact lifecycle; revoke confirms credential/address/telemetry sweep; remove requires revoked state.

### Users & Roles

- **Job:** invite, verify membership, set roles, reset MFA, deactivate/reactivate with credential impact.
- **Actions:** invite/resend/revoke; role; deactivate/reactivate; MFA reset. Keep rows dense; proposal for detail route is held pending API decision.
- **States:** invite pending/revoked/delivered status, active/deactivated, email verification, MFA, directory managed, credential count. Directory-managed membership refuses manual edits.
- **Acceptance:** role/deactivation confirmation names last-owner and credential consequences; invitation mail state is truthful; audit links include actor and target.

## 7. Settings

- **Job:** manage organization, pool/network defaults, authentication/SSO/directory sync, feature flags, alerts, licence, and personal MFA/CLI credentials.
- **Target:** preserve `SettingsRail`/`SettingGroup`, make `section` URL-backed, retain permission-filtered rail. Entity settings move to details. Current actions use organization, pool, MFA enforce, SSO, IdP sync, feature/agent settings, alerting, licence and delete-org endpoints.
- **States:** saving/saved server truth, IdP live/degraded/error, feature opt-in/off, edition unavailable, dangerous-blocked-with-counts. Never put entity-specific health/configuration here.
- **Acceptance:** selected section survives reload/share; settings tabs and panels obey identical permission gate; delete organization can only start after server-provided blockers are zero.

## 8. Observability

### Access Events

- **Job:** investigate whether a request was allowed/denied and which policy/gateway/agent fact decided it.
- **Target:** URL-backed `q,decision,agent,device,gateway,resource,time,sort,dir,limit,cursor`; columns time, decision/reason, subject, gateway, destination, policy version/rule, bytes/freshness. Enterprise gate remains explicit.
- **Acceptance:** event links retain filters; a missing gateway report is displayed as unknown, not device offline; no configuration mutation lives here.

### Audit Log

- **Job:** prove who/system changed what, when, with what outcome/request ID.
- **Target:** URL-backed action, actor, entity, time, request-id filters; columns time, actor/system, action, target, impact summary, request ID. Link from every mutation success/terminal state.
- **Acceptance:** audit filters are shareable; actor/system is never flattened; mutation success copy and audit evidence agree.

## Cross-section acceptance gates

1. Every authorized OpenAPI action is reachable from its owner UI or explicitly classified in the reachability audit.
2. Every unavailable action distinguishes permission, edition, missing prerequisite, and server error.
3. Every destructive action shows exact server-known impact before confirmation and verified outcome/audit after it.
4. Every list supports URL-backed query state before it claims scale; local-only filtering is not the large-list solution.
