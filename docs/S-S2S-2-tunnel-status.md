# S2S-2 — Read-only per-tunnel status

User request: show both IPsec tunnel states independently in the existing connection UI. This adds observation only: no per-tunnel action, automatic failover, route-selection change, permission or connectivity promise. Connection Enable/Disable remains the existing intent action. Applied is never evidence of Up.

## Wire contract

`GET /api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/status` requires existing `org:view`, authorization before selector parsing, and `Cache-Control: no-store`. Response: `{observed_at: null | RFC3339, tunnels:[{id:UUID,slot:1|2,status:"up"|"down"|"unknown",selected:boolean}]}`. Live provider configurations expose exactly their two owned tunnel IDs. Finalized tombstones expose an empty list when tunnel identities have been removed. `selected` describes the configured initial slot1 selection, never measured traffic or automatic failover.

`POST /agent/ipsec/connections/{connectionId}/status` uses the existing mTLS channel and current certificate transaction recheck. Body: `{delivery_id:UUID,desired_revision:positive int64,configuration_revision:positive int64,tunnels:[{id,slot,status,selected}]}`. Exactly two distinct owned tunnel IDs/slots and the configured selection are required. Reject unknown fields, duplicate JSON keys, oversized/multiple JSON bodies, unsupported states and any lineage/certificate/assignment mismatch with static errors. No agent timestamp, secret, counters, raw daemon output or raw failure text is accepted. Success204 after commit.

## Evidence and freshness

The gateway reports Up only after successful independent daemon and keyless kernel observations agree on established IKE, installed CHILD-SA, exact reqid/XFRM identity, endpoints and selectors. Successful complete observation proving absent/down state reports Down. Read failure, partial or ambiguous evidence reports Unknown. The report does not prove application traffic, policy permission or remote return routing.

The control plane writes receipt time using its database clock. A displayed Up/Down requires receipt age between0 and90seconds, exact current desired/configuration/apply-delivery identity and the same still-authorized gateway certificate/assignment. Missing, stale, future, disabled/deleted or invalidated reports project Unknown. A stale receipt timestamp may remain visible to explain age; it never extends freshness. Node polling reports periodically even when apply fails; failures do not become fabricated Down.

## Storage boundary

Existing WireGuard status tables are keyed by WireGuard peer/device identity and cannot represent IPsec tunnel ownership. Migration161 adds one replaceable nonsecret telemetry row per connection, bound to organization/node/delivery/configuration/desired revision and certificate serial, with server receipt and the closed two-slot status payload. Telemetry grants no authority and does not alter connection intent, cleanup, range ownership, audit or secret state. A read performs no writes. Down migration drops only this disposable observation projection; migration160 authority and history remain untouched.

Report transactions reuse runtime authority locking and exact current-principal checks; lineage validation occurs before the observation upsert. Read projection rechecks authoritative state and DB-clock freshness, so disable, replacement or revocation invalidates old Up immediately without relying on a telemetry sweep.

## Required evidence

Write regressions before handlers/store changes: owner/member reader authorization; agent current/stale/cross-node/cross-org certificate and lineage refusals; two-slot identity/selection validation; Up/Down/Unknown mapping; exact90second/future freshness boundaries; no report→Unknown; disabled/revoked→Unknown; no secret/raw error reflection; read-side no writes; migration up/down preservation. Node tests require independent observations and refuse Applied→Up inference. Deterministic generated contracts, API editions, authwalk and focused race tests precede local UI qualification. No cloud access, commit, push or live CP migration is part of this lane.
