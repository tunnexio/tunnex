# IPsec eligibility snapshot — local UI support

Implementation detail companion to [the management UI contract](S-S2S-2-management-ui.md).

GET `/api/v1/organizations/{orgId}/ipsec/eligibility?site_id=UUID&gateway_node_id=UUID` requires existing `org:view` authorization before query validation. It is read-only and sets `Cache-Control: no-store`. There is no schema change, new permission, capability advertisement, activation operation or runtime claim.

Return `{eligible: boolean, reason: eligible|opt_in_required|gateway_unavailable|unsupported|report_stale}`. Missing/disabled organization settings mean `opt_in_required`. The selected Site and gateway must belong to the live organization and the gateway must currently be bound to that Site, active, unrevoked and enrolled with a nonempty certificate serial; otherwise return `gateway_unavailable`. Require exactly numeric capability version 1 (`unsupported` otherwise). Require an existing control-plane `policy_reported_at` receipt no later than the database clock and no more than 90 seconds old (`report_stale` otherwise). Only the fully satisfied snapshot returns `eligible`.

Use a consistent read-only snapshot and database clock. Factor the existing locked create path's gateway predicate without changing create admission. Do not write audit records, settings, organization versions or connection records. Missing/deleted organizations return scoped404; invalid UUIDs return static400; store unavailable returns static503. No provider credentials or secret status appear in this response.

This is advisory selection feedback, not full configuration validation or permission to bypass create. Create remains authoritative and repeats opt-in, ownership, capability and freshness checks under its existing transaction locks, along with exact approved subnet mapping and range checks. Production capability0 gateways remain unsupported.

Acceptance: regression-first exact90-second/future bounds, missing settings with no insert, live-organization/Site/gateway scope, read-side no audit/version/connection writes, router authorization and validation, deterministic generated contracts, focused tests and edition builds. No control-plane restart until the parent agent completes qualification.
