# F07 — Truthful agent audit attribution decisions

Status: **DONE**. Implementation, story-end review, exact local gates and the
AWS DEV box-walk pass. Redacted evidence is under
`walk-artifacts/F07/20260816T0553Z/`.
This story starts from the exact completed F06 content tip `44568f6` and stays
inside the existing compiled-policy, gateway flow-log, access-event ingest,
query API, and released Access Events page. It remains In progress until the
single combined AWS DEV box-walk passes.

## Story-end review and local proof

The security/integrity, concurrency/state, and migration/compatibility review
found and folded four concrete defects before the source freeze:

1. a runtime applied-revision report did not wake the assigned gateway, so the
   artifact could temporarily retain the prior configuration revision;
2. deny aggregation could combine observations from two applied policy/config
   snapshots into one historical row;
3. an unsupported-policy synthetic deny-all could stamp last-good attribution
   even though that artifact was not deciding the packet; and
4. the first notifier query fold duplicated the runtime org-scope contract;
   the authenticated device row lock is now separate while the authoritative
   org/kind/deleted checks remain on the update.

Post-fold focused tests and the exact local composite gates pass: generated
artifacts, migration 0096 on fresh PostgreSQL, both API editions, both builds,
Linux node tests with NET_ADMIN, helper tests and cross-compiles, and the full
web typecheck/1060-test/production-build gate. These are local proofs, not a
substitute for the live box-walk.

## Acceptance question

Can an operator select one AI agent and see a truthful event-time account of
what that agent attempted, which applied policy/rule and gateway adjudicated
it, the route facts, decision and reason, and the agent configuration revision,
without inferring identity from an address or claiming a human/workflow trigger
that was never signed?

## Measured baseline

- `access_events` already preserves the observing `node_id`, matched `rule_id`,
  agent-stamped `src_device_id`, CP-resolved `src_user_id`, destination
  resource/group IDs, L3/L4 route facts, decision, gap markers, per-org sequence,
  and ingest/observation clocks. F07 extends this record; it does not create a
  second audit store.
- The gateway already stamps each flow with the applied policy hash, but the CP
  wire decoder currently drops that field before persistence.
- Source identity is currently rebuilt from `AllowEntry` rows in the applied
  artifact. A source with no grant has no allow row, so its default-deny event
  is honestly unresolved today. F07 must close that exact gap without a CP
  `src_ip` lookup.
- The kernel log prefix already distinguishes a matched grant from the
  default-deny sentinel. The decision and reason therefore have an
  enforcement-owned source; packet tuples do not need to be re-evaluated.
- The existing list API is keyset-paginated and exposes only a server-side
  `denies_only` filter. The released page correctly refuses client-side filters
  that would hide events on unloaded pages.
- `src_user_id` is the accountable owner resolved at ingest. It is not proof
  that the human initiated the traffic. F07 must not label it as a trigger.

## Decisions — LOCKED

### D1 — Extend `access_events`; do not add another audit pipeline

Migration 0096 adds nullable event-time attribution fields to the existing
historical table and its typed query/store contract:

- applied policy hash;
- applied policy protocol version;
- source agent configuration revision;
- source device kind, so agent attribution is preserved at event time;
- a bounded decision-reason enum.

The existing `node_id`, `rule_id`, source/destination identity columns, route
tuple, sequence and clocks remain canonical. The same enriched `Event` value
continues to feed every persistence/query projection.

Rejected: a separate agent-events table, a generic event framework, or copying
low-volume `audit_logs` into the high-cardinality access-event path.

### D2 — The compiled artifact carries a complete attribution subject map

Add one observability-only `subjects` collection to the compiled per-gateway
artifact. Each entry is the server-assigned source address, canonical device
ID, device kind, and nullable applied agent-runtime revision captured in the
same policy snapshot. It includes every active address-bearing device on the
gateway, including an agent with zero grants.

The node atomically installs this map with the applied artifact and stamps flow
events from it. The map is excluded from enforcement matching and the canonical
enforcement hash. Old nodes may ignore the additive field and will produce
events with nullable F07 attribution rather than fail or weaken enforcement.
No protocol-version bump is required solely for hash-excluded observability
metadata; the event separately records the applied artifact's existing
protocol version.

Rejected: deriving device identity from `src_ip` at ingest, adding fake allow
rules for zero-grant agents, or putting owner/user identity in the gateway
artifact.

### D3 — Policy and configuration facts are stamped at event time

The node stamps the applied artifact hash and protocol version from the same
successful in-memory artifact that owns the subject map. For an AI agent, the
subject entry also stamps the applied managed-runtime configuration revision
captured by the compiler snapshot. These values are persisted verbatim through
ingest; the CP does not replace them with whatever is current when the report
arrives.

`node_id` remains server-owned: the mTLS-authenticated gateway channel supplies
it, and no request body may choose another gateway identity.

An absent hash/version/revision remains null and renders “Not recorded”. Zero
is not used to fabricate an unavailable event-time fact.

### D4 — Source agent identity is canonical; human trigger attribution is absent

The CP accepts a stamped source device only after the existing org-scoped
device-ID verification. An event is agent-attributed only when that verified
device is `kind=agent`; a foreign, malformed, or non-agent claim cannot seed an
agent identity into the historical log.

The UI may join the stable agent UUID to a current roster label for readability,
but must mark that label as current, not event-time. It does not show the
accountable owner as “triggered by”, “ran by”, or equivalent. Signed
human/workflow provenance remains absent and deferred.

### D5 — Decision reasons are a small enforcement-owned enum

Persist exactly these initial reasons:

| Event decision | Reason |
| --- | --- |
| `allow` | `matched_grant` |
| `deny` / `deny_aggregate` | `no_matching_grant` |
| `terminated` | `grant_revoked` |
| `gap` | `events_dropped` |

The reason comes from the kernel-stamped grant/default-deny prefix or from the
existing explicit terminated/gap event constructors. It is not reconstructed
by running today’s policy compiler against an old packet tuple. Unknown future
reasons are refused at the schema/wire boundary until deliberately added.

### D6 — “Route” means the observed and resolved facts already owned by the event

The detail view presents source IP, destination IP, protocol/port, captured
destination resource/group IDs, and observing gateway. It does not invent a
DNS name, network path, matched site, or reachability explanation. F08 owns the
non-mutating reachability evaluator and step-by-step blocker analysis.

### D7 — Server-side historical identity filters; no client-side partial-feed filtering

OpenAPI originally added optional `src_agent_id` to the existing keyset list
endpoint. The additive identity follow-up also exposes `src_device_id`,
`src_user_id`, and `src_kind`, and accepts mutually exclusive `src_device_id`
or `src_user_id` filters. Each query combines with `denies_only` and the
existing cursor while preserving organization scope and ordering.

Filters match the immutable attribution already stored on the event; they do
not join or validate against the live device/member roster. That keeps a
deleted identity's history queryable and makes a missing or foreign UUID an
empty result rather than an identity oracle. `src_agent_id` remains a
compatibility alias constrained to events whose persisted kind is `agent`.

The released page fetches current rosters only for selector labels and sends
the selected persisted identity ID to the server. It never filters only the
rows already loaded, and an unavailable current label never rewrites the
historical UUID.
Selecting another organization synchronously clears rows, agent options,
labels, filters and open details before the next request can commit.

### D8 — Reuse `policy:view`; add no F07 mutation or permission

Access events remain read-only and keep the existing `policy:view`,
permission-before-edition boundary. F07 adds no writer and no new permission.
Machine ingest remains on the authenticated gateway channel. Agent runtime
bearers cannot read or write access events.

### D9 — The detail timeline is a projection of one immutable event

Selecting a row opens a detail timeline with four factual stages:

1. source identity and configuration revision stamped by the applied artifact;
2. gateway and applied policy hash/protocol version;
3. matched rule plus observed destination/protocol/port;
4. decision/reason and CP ingest sequence/time.

There is no second detail endpoint: the list row already contains the immutable
facts. Current agent/gateway/rule labels are optional presentation joins with
UUID fallback and explicit current/deleted wording. A failed auxiliary label
lookup cannot withdraw the event itself or replace an ID with a guessed name.

### D10 — Historical rows stay honest and rollback is preservation-first

Existing rows are not backfilled with a current policy hash, version,
configuration revision, or guessed agent identity. The bounded reason may be
backfilled only where it is a deterministic encoding of the stored decision
and rule presence; otherwise it remains null.

Migration down succeeds only while every 0096 attribution field is null. Once
new attributed events exist, down refuses and preserves all event rows and
values. Up-again on an empty/new-field-free database is clean.

### D11 — Reuse the existing explicit flow-log opt-in

F07 does not silently enable collection. Enterprise unlock stays separate from
the existing gateway flow-log collector configuration, which remains explicit
and default off. The UI must distinguish “no matching events” from an
unavailable/disabled/unhealthy collector using the existing access-log health
surface and an instrument-first live check.

## Lean implementation slices

1. **Artifact and wire:** add the hash-excluded subject map, event-time policy
   metadata, agent runtime revision, and bounded reason stamping. Prove a
   zero-grant default deny is agent-attributed without a CP address lookup.
2. **Persistence and API:** migration 0096, sqlc/store/ingest preservation,
   org-scoped server filter, OpenAPI/codegen, and both-edition/no-oracle tests.
3. **Released UI:** server-backed agent selector, current-label joins, factual
   detail timeline, unavailable/deleted states, DOM absence and rapid org-switch
   cancellation.
4. **Review and gates:** story-end multi-finder review, fold only dispositioned
   findings, then exact local composite gates once.
5. **One combined AWS DEV walk:** exact content commit, one disposable agent,
   one disposable rule/destination and one reporter gateway. No partial slice
   deployments.

## Single combined AWS DEV acceptance walk

Run only after all F07 product code, review and exact-head local gates complete:

1. Record exact commit/images, schema/backup rollback point, Enterprise state,
   collector health, and unrelated agent/gateway/event counts.
2. Enable/verify the existing flow-log instrument only for the disposable
   reporter. Prove a known packet produces an event before interpreting an
   empty feed.
3. With a zero-grant active agent, send one denied flow and prove the persisted
   event carries the agent ID/config revision, gateway, applied policy
   hash/version, `deny`, and `no_matching_grant`, while no human trigger appears.
4. Add one agent-source grant, refetch/apply it, send one allowed flow, and prove
   the matched rule, route tuple, `allow` and `matched_grant` are stamped by the
   applied artifact. The agent filter must return only this agent’s rows across
   the real API and released route.
5. Rename or delete only the disposable rule after ingestion. Historical IDs,
   route facts, policy hash/version and decision/reason remain; the UI labels a
   missing/current name honestly instead of rewriting the event.
6. Prove permission/edition/no-oracle behavior and a rapid organization switch
   that leaves no prior agent/event/detail fact in the new organization DOM.
7. On disposable PostgreSQL, prove 96→95 empty success, 95→96 up-again, and
   non-empty rollback refusal preserving attribution fields and event rows.
8. Remove only the disposable agent/rule/event harness and host files; restore
   collector configuration. Preserve unrelated gateways, users, policies,
   events, backups, TUN and base prerequisites.

## Strict non-goals

- No human, workflow, model, tool-call or MCP attribution without signed
  provenance.
- No `src_ip`→device/user inference, historical owner rewrite, or current-policy
  replay against old traffic.
- No JSONL/SIEM export, alerting/webhooks, aggregate dashboards or verdict totals
  (F11 and existing deferred access-log export work).
- No F08 Test Access evaluator or active probe.
- No F09 groups/templates and no policy-authoring surface on Access Events.
- No generic audit/event framework, tracing system, packet capture, L7 payload
  inspection or prompt-injection claim.
- No F04/F05 runtime/rotation state-machine rewrite and no F06 RBAC redesign.

## Stop condition

Stop F07 when one zero-grant deny and one matched-grant allow from a real managed
agent are truthfully attributable end to end; the server-side filter and detail
timeline render only recorded facts; nullable history, no-oracle/org-switch,
rollback preservation, both editions, exact-head CI, review and the single AWS
walk pass. Do not add analytics, exports, human attribution or diagnostics to
make the story look larger.

## Unresolved decide-items

None at commit-one. The repository already owns the enforcement artifact,
gateway-authenticated flow wire, historical event store, read boundary and
released page. Any newly discovered need to infer identity, widen the protocol
into L7, or fail enforcement for missing observability is a new decide-item and
halts product code.
