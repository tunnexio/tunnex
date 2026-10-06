# Database Workspace — epic and story plan

Status: **Planning only; no implementation or deployment performed.**
Prepared: 2026-10-06. Story namespace: **DW**.
Source baseline: `feature/browser-access`, commit `cc0ab25eefd938757797552b26600b6da1930877`.
Working product name: **Database Workspace**. Sidebar placement and final branding remain design decisions; this plan does not change Tunnex Shield.

## Customer outcome

An administrator registers a private database, selects an enrolled gateway, verifies database TLS identity, configures database authentication and grants bounded access to existing Tunnex users/groups. A user selects an authorized database and opens a browser SQL workspace without a public database endpoint or end-user VPN. Every connection retains the Tunnex actor identity; database privileges remain enforced by the database.

Example: a developer requests 30 minutes of PostgreSQL read access, receives approval, runs a bounded SELECT, and loses further access when the grant expires. A database administrator can inspect access events without receiving sensitive query results by default.

## First release and follow-ups

**Recommended v1:** PostgreSQL only; browser SQL; database-enforced read-only roles; private gateway connectivity; mandatory verified TLS; explicit grants; inline MFA; bounded results; connection/session events; manual cancellation; administrator termination. Capability remains opt-in until qualification passes.

- Register existing databases and existing restricted PostgreSQL login roles. No automatic schema, role or permission changes during registration.
- Support an administrator-owned credential reference backed by an encrypted secret store. No passwords in browser state, URLs, API read responses or gateway assignment payloads. Resolve a credential only after access admission; expose it only to the gateway's bounded connection worker.
- Prefer named per-person database roles where customers need database-native individual attribution. Shared roles retain Tunnex attribution but cannot claim individual identity in PostgreSQL's own logs.
- Browser users never receive the stored database credential. PostgreSQL credentials necessarily exist in worker memory while authenticating; do not claim zero-secret handling.
- Default query-text/result persistence OFF. Capture safe connection/execution metadata; enabling query-text audit requires a separate reviewed retention and privacy policy. Literal values can contain secrets.
- CSV export, writes/DDL, MySQL, native GUI/CLI connections, dynamic Vault credentials, cloud IAM authentication and database-specific activity controls are separate follow-ups.
- Native database clients are not part of browser v1. Arbitrary TCP routing alone is not a database-authenticated access feature.

## Reuse and new work

| Existing Tunnex capability | Reuse | New Database Workspace responsibility |
| --- | --- | --- |
| Users/groups, RBAC, MFA, parent sessions | Actor, permissions, factor verification, session authority | Database-specific admission and action permissions; reuse existing MFA freshness policy rather than inventing an independent timer |
| Enrolled gateways, control channel, desired-state/leases | Gateway identity, task delivery, bounded authorization | PostgreSQL connection worker and database protocol/result messages; do not reuse terminal frames for SQL |
| App Access request/approval patterns | UX and authority patterns | Database-resource requests and decisions under their own RBAC; existing app grants cannot authorize a database |
| Secret encryption and key lifecycle | Established envelope encryption and recovery patterns | Credential references, rotation, worker delivery and failure semantics |
| Access Events, Audit Log, alerts | Filters, actor attribution, safe operational events | Database session/execution metadata, redaction and database-specific failures |
| Compose/Helm/install, backup/restore | Artifact and lifecycle conventions | Gateway capability advertisement, optional module config, upgrade/restore/disable contracts |

Existing packages are candidates for reuse, not evidence that PostgreSQL transport or secret handling is already qualified.

## Customer journeys and UI

Admin: **Databases → Add database → address/port/database/gateway → verify TLS → credential reference/restricted role → connection check → enable → Access**.

Member: **My databases → Connect → inline MFA if needed → SQL editor/results → Cancel or Disconnect**. Where requests are enabled, unavailable access shows **Request access**, reason and duration.

Use existing inventory/table/dialog/status conventions from Applications and Servers. Show database engine, name, private endpoint, gateway and readiness in the inventory. Put grants behind each database's Access action. Sessions show actual user sessions; connection checks have a separate filter. Keep instructions collapsed and error recovery next to the failed action. Never display raw credentials or query text in generic notifications.

Browser v1 presents one SQL statement per execution, one active execution per session, no interactive transaction workflow, and no shell. Unsupported transaction/control/multi-statement requests are refused. Database-role permissions remain the security boundary; SQL parsing is not a substitute for them.

## Stories and per-story tasks

Every story includes UI, frontend and backend work or an explicit reason why no new screen is required. A story is complete only when its negative cases and acceptance evidence pass.

| Story | Customer deliverable | UI/design tasks | Frontend tasks | Backend/gateway tasks | Acceptance and dependency |
| --- | --- | --- | --- | --- | --- |
| **DW-0 — Authority and feasibility** | Prove the PostgreSQL approach before building the full workspace | Admin/member journey, trust/credential states, compact failure prototypes | Local fixtures for denied, unconfigured, ready, expired and disconnected states | Decision record; disposable PostgreSQL spike through an enrolled gateway; choose driver/transport; prove verified TLS, restricted role, cancellation and authority leases | Wrong CA/hostname, denied role, expired admission and lost authority fail closed. No UI readiness inferred from an open port. Required before DW-1 |
| **DW-1 — Resource registry** | Register a private PostgreSQL database | Inventory and Add/Edit dialogs; endpoint, database, gateway, state; Disable/Remove confirmation | Form validation, tenant-safe fetches, pagination, capability/permission gates, dirty-form handling | OpenAPI, migrations, resource revisions, gateway binding, soft removal, separate manage/view/use/grant/session/audit permissions, atomic audit | Tenant isolation; member cannot inspect protected connection settings; disable prevents new admission; removal retains history. Depends DW-0 |
| **DW-2 — Trust, credentials and checks** | Know exactly why a connection is ready or blocked | TLS trust choice, hostname/server-name, CA input, secret reference, restricted role, Test connection; concise repair hints | Secret write-only controls; no prefilled/readback password; staged check state and stale revision handling | Mandatory PostgreSQL TLS with certificate chain and hostname validation; reviewed custom CA trust; credential encryption/reference, gateway-only bounded delivery; separate DNS/TCP/TLS/auth/database/role checks | Reject insecure TLS modes, wrong identity and invalid credentials; errors/logs redacted; credentials absent from API reads/backups without encryption; checks do not grant user access. Depends DW-1 |
| **DW-3 — Admission and lifecycle** | Open and end an authorized database session | Connecting/Connected/Expired/Unavailable states; inline MFA; clear reconnect action | Session create/connect/disconnect, expired grant handling, reuse fresh MFA, no automatic query replay | Current user/group/grant/resource/MFA checks; session leases; authenticated browser-to-CP-to-gateway channel; bounded connection worker; parent logout/disable/revoke handling | Proposed termination bound at most 30 seconds, proved under lost notifications and CP partition; refuse new work without current authority; no promise to undo already completed work. Depends DW-2 |
| **DW-4 — SQL editor and execution** | Run a safe, bounded read query | Editor, explicit Run/Cancel, duration, results grid, NULL/error display; responsive keyboard flow | Single-statement submission, request IDs, one active execution, virtualized grid, escaped values, loading/cancel states; prevent accidental duplicate submits | Structured execute/results protocol, parameter support, bounded result batches, PostgreSQL restricted role validation, per-statement read-only transaction, statement timeout, row/byte caps | SELECT success; denied writes/DDL; role with excess privileges refused under supported readiness policy; no SQL-regex security claim; timeout/slow-consumer/cancel tests. Depends DW-3 |
| **DW-5 — Schema explorer** | Find available tables and columns without memorizing names | Searchable schemas/tables/columns; column types; explicit preview action | Lazy, bounded metadata fetches; permission errors; preview does not run merely on selection | Catalog queries under the admitted database role; identifier quoting; catalog limits; schema/table visibility filtering | Inaccessible objects not exposed beyond database-role visibility; hostile identifiers handled safely; no background unbounded scans. Depends DW-4 |
| **DW-6 — Grants and access requests** | Admin grants access; member requests time-limited access | Per-database Access dialog; role selector, user/group, duration; request inbox with approve/reject; active/expired views | Request/grant forms, scoped subject lookup, impact confirmation, inline MFA, status refresh | Database-role allowlist; separate bounded grant/request APIs; no self-approval by requester; atomic approval, expiry, revoke and group-change evaluation | Grant to one database/role cannot authorize another; concurrent approve/revoke and expiry tested; approval does not repair failed readiness. Depends DW-1–3 |
| **DW-7 — Sessions, events and privacy** | Inspect and terminate exact sessions without storing result data | Sessions table, server/user/database-role/time/status; End confirmation; Access Events filters | Pagination, safe details, terminate/retry states; checks separate from real sessions | Session/execution events with actor/resource/role/duration/outcome/counts; no SQL/result/password fields by default; retention and explicit audit permissions | Cross-tenant/session access denied; sensitive query literals/results absent from DB/logs/events; termination requested vs confirmed shown honestly. Depends DW-4, DW-6 |
| **DW-8 — Rotation and recovery** | Credentials can change and services can restart safely | Credential rotation status, connection recheck, disconnected/reconnect hints | Stale credential version/readiness handling; reconnect creates a fresh session and never reruns a query | Credential versioning, bounded secret cache, encryption-key recovery; new sessions use new credentials; readiness reset on trust/destination/role changes; CP/gateway restart cleanup | Rotation/outage and encrypted backup/restore verified; existing-session rotation behavior documented; crashes clean abandoned workers; query outcome can be unknown after disconnect. Depends DW-2–7 |
| **DW-9 — Packaging and capacity** | Install and operate the module with predictable limits | Module availability and incompatible gateway explanation; concise operations settings | Capability-based controls, bounded preferences and clear limit messages | Signed gateway artifact, Compose/Helm/install configuration, migrations, quotas, metrics, alert hooks, upgrade/rollback and module disable runbooks | Disabled by default; current VPN/AI/Shield unaffected; fresh install/upgrade/rollback; bounded CPU/memory/connections/results; no unqualified HA claim. Depends DW-8 |
| **DW-10 — Integrated qualification** | Prove complete admin/member flows | Visual review against existing UI; accessibility, empty/error/loading/mobile layouts | Screen census, component tests, full web gates, browser E2E for create/check/grant/connect/query/cancel/revoke | Real isolated PostgreSQL tests in both editions; query/role/TLS red cases; real gateway transport; fuzz/protocol limits; concurrency and authority-loss matrix | Evidence tied to exact source/artifacts; configured PostgreSQL/browser versions documented; no mock-only completion. Depends DW-1–9 |
| **DW-11 — Customer acceptance and release** | Validate deployment in a customer-like private network | Customer walkthrough and concise setup/troubleshooting guide | Verify customer browser flows and supported feature limits | Private-network deployment, restrictive firewall, real CA trust and restricted roles, rotation, outage, revoke bound, capacity, restore and rollback walk | Explicit release approval after evidence. Deployment/cloud mutations are separately authorized. Depends DW-10 |

## Security and execution contract

1. The database role is authoritative. Read-only transactions add defense in depth but do not make an overprivileged role safe: SELECT can execute functions or extensions with side effects. The supported role/setup contract must reject superuser, role/database creation, replication, bypass-RLS and dangerous inherited/function privileges; customer-defined functions/extensions need an explicit supported policy. If readiness cannot establish that policy, refuse ready status or narrow the supported scope.
2. PostgreSQL RLS and object permissions remain customer-controlled. Tunnex does not infer row-level authorization from a Tunnex group.
3. Credentials never go to browser clients. Workers fetch only the selected resource/role credential under a short-lived, scoped authorization; assignment metadata contains references, not reusable secrets.
4. Require verified TLS with a trusted chain and expected hostname/server-name, including private custom CAs. No `sslmode=disable`, opportunistic downgrade or blanket certificate-ignore option. CA replacement requires explicit review and fresh checks.
5. All query/result messages are authenticated, tenant/session bound, length limited and flow controlled. Escape output; do not render database text as HTML.
6. Cancellation/termination blocks further execution and closes the connection within a measured bound. It cannot undo delivered results or guarantee that an already accepted external side effect never happened. A dropped response can leave execution outcome unknown; never automatically retry queries.
7. Turning a resource off revokes admissions and terminates sessions; editing connection identity invalidates readiness. Existing audit records are retained. Configuration checks and credential administration never imply use permission.
8. Browser SQL has no result persistence by default. Query-text auditing and export require separate permission/privacy/retention design before enabling them.

## Proposed starting limits — validate in DW-0/DW-9

| Limit | Proposed default |
| --- | --- |
| Execution timeout | 30 seconds; administrator hard maximum 120 seconds |
| Result delivery | Maximum 1,000 rows and 5 MiB per execution; clearly marked truncated |
| SQL request | Maximum 64 KiB; single statement |
| Concurrency | One active execution/session; initial gateway cap 20 database connections |
| Idle session | 10 minutes |
| Maximum session | 60 minutes or remaining grant duration, whichever is shorter |
| Access grants | Reuse existing bounded-grant conventions; no permanent grant default |
| Authority lease | Proposed maximum 30 seconds; qualify against backend statement execution and partition behavior |

These are planning defaults, not tested capacity promises. Row caps must bound work/result delivery, not merely hide extra rows after buffering the entire response. Long-running queries require server-side timeout/cancellation and connection closure on lost authority.

## Follow-up stories — outside v1

| Story | Deliverable | Additional proof |
| --- | --- | --- |
| **DW-F1 — Native database clients** | Scoped local endpoint for psql/DBeaver/DataGrip using existing Tunnex client identity | PostgreSQL protocol proxy, native-client TLS/auth behavior, grant expiry across pooled connections; no blanket TCP access |
| **DW-F2 — Dynamic credentials** | Vault or approved cloud IAM integration with short-lived database identities | Lease renew/revoke, secret-source outage, DB privilege boundary, customer-owned connector permissions |
| **DW-F3 — MySQL** | Second database engine using the same customer journey | Separate protocol, TLS/authentication, role model, cancellation and native engine tests |
| **DW-F4 — Controlled write access** | Explicit writable roles and approved privilege windows | Transaction/unknown-outcome semantics, role/DDL authority, confirmation scope; no promise that query-text parsing prevents destructive work |
| **DW-F5 — Export and query audit** | Permissioned bounded CSV export and opt-in query-text audit | Formula-injection protection, download lifecycle, sensitive literal/redaction limitations, retention, quotas and privacy acceptance |

## Decisions to confirm before implementation

Recommended starting assumptions: PostgreSQL browser-first; read-only existing restricted roles; no query/result persistence; existing MFA freshness policy; credential references with established envelope encryption; no customer-cloud auto-provisioning.

DW-0 must settle: exact PostgreSQL versions, driver/transport ownership, custom function/extension policy, shared versus named roles, secret-store availability, supported editions and sidebar placement. If a safe restricted-role contract is infeasible, report the limitation before expanding scope; do not quietly advertise generic safe SQL execution.

## Execution order and completion boundary

Execute DW-0 first. Then DW-1/2, DW-3/4, DW-5/6, DW-7/8, and DW-9/10/11. UI fixtures may proceed alongside contract design, but runtime behavior cannot precede its authority/TLS/role proof. Avoid invented delivery dates until DW-0 produces a measured feasibility result.

Planning completion means this epic/story/task table is reviewable. Implementation completion requires every v1 story and acceptance check. Production/customer release completion is DW-11, not a green local test run.

Reference: [Teleport database access](https://goteleport.com/docs/enroll-resources/database-access/) is a market comparison; its architecture is not proof of Tunnex's implementation.
