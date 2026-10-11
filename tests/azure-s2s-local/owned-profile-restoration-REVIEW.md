# Source-only owned profile restoration candidate

Base: d1f5c201257c45c061ba05a0fe1b761423761bfe. This record is local qualification, not cloud execution or profile acceptance. Existing private D/M/R, grants, old staged sources and root checkout are unchanged.

## Static connection settings

`deploy/azure/configure-owned-static.py` exposes `prepare/apply/read/reconcile/restore`. Each invocation uses a new private output, a private state path, and (for writes) actual fresh normal disabled cleanup plus independently attested native absence/hash. `prepare` additionally takes the actual immutable normal binding. `restore` takes current disabled successor binding with `original_connection_id` pointing to the original saved normal UUID; all org/Site/gateway/namespace coordinates remain exact.

Prepare saves exact public connection, LNG and full gateway response bytes and hashes. It never reads keys. Apply reserves LNG prefix and connection BGP writes separately before dispatch. Restore uses the saved prefix list (including []) and saved BGP value. Each write has an exclusive durable marker and state written before CLI; timeouts/nonmatching response/pending readback leave reservations intact. A reserved operation is never replayed. Restore may issue a different, unreserved step after genuine readback establishes the partial result. Restore connection first, then LNG, while the actual normal successor is disabled and strict native absence remains fresh. Final observation alone never proves tunnel readiness.

Protected scope includes all fields in the explicit nonsecret connection/LNG GET projection, the full gateway projection, both PIP identities, VNet/subnets/address spaces and existing DNS/LB/resolver protected projections. This is not a claim to preserve arbitrary future fields omitted by the explicit connection projection; no whole connection PUT occurs. Unrecognized gateway restore fields refuse instead of being discarded.

The legacy `discover-owned-profile.py aa-static` mutation path now refuses before any Azure call. Discovery remains available. This removes the unreserved two-write entry point.

## Standby conversion restoration

`deploy/azure/convert-owned-standby.py` retains existing conversion phases and adds `restore`. It restores both original IP configurations and both custom APIPA mappings from the exact byte snapshot, using writable fields only, with one exclusive restore reservation. PIP2 is never deleted. Every unrelated gateway property must compare exact after documented server fields are excluded. Restore requires fresh genuine disabled/absence evidence for the current successor, with original lineage binding. After an uncertain restore, only `read/reconcile` is allowed; exact original AA observation settles it. Provisioning may take longer than evidence freshness; renew actual observations, never extend their timestamps.

The conversion state protects the original connection/LNG hash. Restore static connection/LNG settings to that baseline BEFORE gateway AA restoration; otherwise the topology helper intentionally refuses. Prepare conversion only after original cloud Default/BGP contract has been genuinely observed. No resource resize, deletion, public IP provisioning, key retrieval, timer change, CP mutation or permission grant exists in these helpers.

## Advertised route read

`deploy/azure/read-owned-advertised-prefixes.py` is bastion-only, exact owner/subscription/Default-BGP bound, bounded to65 seconds and262144 bytes. It accepts only canonical IPv4 prefixes from a complete documented `value[]` envelope or explicit CLI array. Unknown fields, pagination, duplicate JSON keys, malformed/null/noncanonical rows refuse. It does not print raw ARM output/stderr. A successful projection proves only Azure advertised-route observation, not received NLRI, native acceptance, max-prefix causality or packets. The previous unavailable read is not retrospectively attributed to shape or timeout.

Microsoft documents `GatewayRouteListResult.value` and the seven allowed route fields: https://learn.microsoft.com/en-us/rest/api/network-gateway/virtual-network-gateways/get-advertised-routes?view=rest-network-gateway-2025-07-01 . CLI gateway update/list-advertised-routes and generic setters: https://learn.microsoft.com/en-us/cli/azure/network/vnet-gateway?view=azure-cli-latest . Actual CLI serialization and restored service behavior remain a live acceptance prerequisite; if server response is unexpected, retain private snapshots/reservations and refuse without retry.

## Offline validation

`PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/azure-s2s-local -p 'test_owned_*py' -v`

66 tests pass. New fixtures prove original-empty-prefix restoration, write timeout reservation/no replay, standby restore timeout and exact AA reconciliation, lineage/namespace/foreign protected property refusal, server-field-only restore payload, old-Python fractional timestamp normalization, both route envelope shapes and malformed/partial route refusal. Constructed fixture evidence is parser/helper qualification only; no live absence or cloud outcome was manufactured.
