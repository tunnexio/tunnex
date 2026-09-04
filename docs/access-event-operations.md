# Access-event ingestion and retention

Access Events is a real gateway-to-control-plane evidence pipeline. The web UI
does not create sample records and an empty list is not proof that collection is
healthy.

## Data path

1. In enforcing mode, the gateway's nftables allow rules and default-deny tail
   send eligible `ct state new` packets to NFLOG. The log prefix carries the
   matched rule ID, or a deny marker; logging cannot change the packet verdict.
2. `tunnex-node` reads NFLOG, stamps the successfully applied policy and source
   attribution, and buffers records in a bounded in-memory ring.
3. Every five seconds the node drains and, when it has events or a loss count,
   sends a batch to `POST /agent/flow-events` over its existing mutually
   authenticated control channel. A failed batch is
   represented by a later `gap` record rather than retried as a possible
   duplicate, provided the same agent process remains alive until a later
   delivery succeeds. A restart before that success loses the in-memory loss
   count; durable gateway spooling is not part of v1.
4. The API derives the node and organization from the client certificate,
   accepts a stamped source device only after an organization-scoped lookup,
   resolves that device's owner at ingest, reserves a monotonic organization
   sequence, and inserts the batch transactionally into `access_events`. It
   never infers a device or person from `src_ip`.
5. `GET /organizations/{orgId}/access-events` reads the retained PostgreSQL
   window with an organization-scoped keyset cursor. `/access-events` renders
   that response directly.

The event response preserves optional `src_device_id`, `src_user_id`, and
`src_kind`. For an agent row, the compatibility field `src_agent_id` is the
same persisted device ID. The user ID is the accountable device owner resolved
at ingest; it is not evidence that the human initiated the traffic, and it is
not rewritten if the device is later reassigned. Device and user labels are
live display data and may be unavailable after rename, removal, or deletion.

The list endpoint accepts `src_device_id`, `src_user_id`, or the compatible
`src_agent_id` filter. At most one source identity filter may be present. Each
matches the immutable event row inside the requested organization and composes
with `denies_only` and the keyset cursor. Deletion from the current roster does
not hide retained matches. An ID with no matching retained row—including an
unknown or foreign UUID—returns an empty page without probing the live device
or member roster. Supplying multiple identity filters returns HTTP `400` with
the stable code `invalid_access_event_identity_filter`.

Migration `0128_access_event_identity_filters` atomically swaps the partial
agent lookup index for a general device index and adds the equivalent user
index. These are plain transactional index builds, so apply the migration in a
controlled window: the per-organization retention cap does not bound total
table size, and index construction can briefly block event writes.

Collection uses NFLOG group `100` by default. Set
`TUNNEX_FLOWLOG_GROUP=0` only when collection is intentionally disabled. The
gateway heartbeat reports `active`, `disabled`, `source_error`, or
`delivery_error`; the API derives `stale` when the heartbeat ages beyond the
gateway freshness window, and a fresh older agent that has never reported this
capability is shown as `unknown`. A quiet `active` gateway and a disabled collector are
therefore different operator states. The same heartbeat carries the latest
gateway-observed and successfully-delivered times; the control plane adds its
own receipt time and the latest retained event time.

The periodic `POST /agent/report` heartbeat carries `flow_log_state` plus
`flow_log_last_observed_at` and `flow_log_last_delivered_at` once those
timestamps exist. The latter is the time a flow batch (or loss-gap report) was
successfully accepted, not merely the time a delivery was attempted.

Access-event records are currently produced only while Zero Trust is in
`enforcing` mode. Mesh/off mode installs no policy decision log rules.

## Retention policy

Retention is organization-scoped and configured under **Settings → Data
retention**. It is not an AI-agent setting and it is not a destructive
flush-all control.

Defaults and hard bounds:

| Setting | Default | Minimum | Maximum |
| --- | ---: | ---: | ---: |
| Retention age | 30 days | 1 day | 3,650 days |
| Scheduled cleanup interval | 60 minutes | 5 minutes | 1,440 minutes |
| Per-organization pruning target | 100,000 rows | fixed | fixed |

The earlier of the configured age and the fixed row target wins. Because cleanup
is asynchronous and bounded, ingestion can temporarily take a tenant above
100,000 rows until the scheduler catches up. Age is measured
from the API's trusted `created_at` ingest clock, never the gateway clock.
Changing the duration makes older rows eligible for the next run; it does not
delete rows inside the settings transaction.

On upgrade, an organization that already holds access events and has no durable
run is due on the first elected scheduler poll (normally within one minute). The
60-minute default is the interval between completed runs, not an initial grace
period. The effective 30-day/100,000-row policy is unchanged from the legacy
sweep, but an unhealthy or paused old sweep may have left newly eligible rows.
Inventory that exposure and verify the documented database/master-key backup
before starting the new API. There is no supported pre-start scheduler pause for
staging a non-default policy. Once a settings or run row exists, migration 0127
refuses a schema downgrade; recovery is restore-from-backup, consistent with the
forward-only upgrade contract.

Only organization owners and admins hold
`access_event_retention:manage`. Settings changes use revision-based optimistic
concurrency and are audited. “Run pruning now” accepts only an idempotency key
and applies the persisted policy; it accepts no caller-selected cutoff. Manual
requests are audited once when claimed, while completion or failure is the
authoritative durable per-organization run record. Scheduled housekeeping uses
that same run history without flooding the human audit log.

The elected control-plane writer checks due organizations once per minute.
Each run deletes at most 1,000 rows per transaction and at most 100 batches.
When more eligible rows remain, status reports `more_pending` and the next tick
continues the backlog. A unique running-run constraint prevents scheduled and
manual work from pruning the same organization concurrently.

Every irreversible batch is fenced at the database boundary. The pruning
function accepts only an exact retention-run ID, locks the organization and
run, verifies a live lease and the current effective policy, derives both the
age cutoff and row-cap boundary from durable state, and records the deleted-row
and batch counters in the same transaction as the delete. Direct deletion and
truncate operations fail with `access_events_delete_not_authorized`; hard
organization deletion remains able to cascade its historical events. This also
makes pre-fence control-plane schedulers fail closed during a rolling upgrade
instead of applying their fixed legacy policy. See [upgrade.md](upgrade.md) for
the version-boundary procedure.

The scheduler creates a new run only when at least one event is currently
eligible by age or row cap. Expired claims are still recovered even if their
last committed batch removed every eligible event. Automatic terminal history
is capped at the newest 1,000 scheduled runs per organization; manual runs are
retained so an old idempotency key continues returning its original result.

## Operational checks

For a gateway that shows no events:

1. Confirm the organization is in enforcing mode and the gateway collector
   state is `active` in Access Events.
2. On the gateway, confirm `TUNNEX_FLOWLOG_GROUP` is non-zero and both `nft list
   table ip tunnex` and `nft list table ip6 tunnex` contain the expected
   `log prefix "tnx:` clauses for enabled address families.
3. Create a genuinely new connection. Established conntrack traffic bypasses
   the new-flow log rule.
4. Check the gateway for `flowlog_source_failed` or
   `flowlog_report_failed`, then correlate control-plane ingest logs by node ID,
   timestamp, and HTTP status. The agent does not propagate a control-plane
   request ID back into its own log.
5. Confirm `organizations.flow_seq` advances with the inserted rows. The
   sequence is never reset by retention, so zero proves that no batch has ever
   committed for that organization.

`source_error` is sticky because the NFLOG source is opened once; restart the
agent after correcting the source. `delivery_error` clears after a later flow or
gap report is accepted. A stale heartbeat takes precedence over the last
reported collector value.

For retention, use the Data retention status rather than inspecting process
memory. A failed run stores only a bounded error code for the UI; detailed
database errors remain in control-plane logs. Re-running with the same manual
idempotency key returns the original run, while a new key starts another
bounded pass.
