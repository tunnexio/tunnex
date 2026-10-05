# Ready connection delivery

Expose public connection metadata only through an authorized sandbox detail read,
and only for current Ready/started/unexpired/current creator and active peer.
Persist the immutable generated SSH public host key and its fingerprint when
trusted assets are materialized, outside ordinary credential storage. No private
host/client key, bootstrap token, runtime credential or host asset path enters
API inventory. Re-read current creator/template/skill eligibility before showing
connection details; losing eligibility must hide them immediately, without
waiting for a reconciler to repaint Ready.

Return private IPv4, fixed username sandbox/port22, pinned public host key and
SHA256 fingerprint. UI provides copyable SSH and dedicated known_hosts content
with normal strict checking, plus existing local Codex/Claude instructions after
SSH. Do not require a hosted agent, MCP or model endpoint. Explain that the local
terminal must already be connected to the organization's Tunnex private network.
Preserve the client's own private key; public admission uses .pub contents only.
Do not offer StrictHostKeyChecking=no, automatic trust-store modification or a
browser-delivered private key. Hide connection instructions during start/stop/
expiry/error and keep template/skill choices explicit.

Tests must cover owner/organization isolation, admission withdrawal despite a
stale Ready row, non-Ready suppression and public-only response content. Generated
OpenAPI Go/TypeScript are the source contract; UI copy failures are visible and
never imply a successful connection. This is source work, not live qualification.

Validation on 2026-10-03: affected PostgreSQL sandbox/config suite passed
46.660 seconds; HTTP sandbox contract tests passed1.114 seconds; web typecheck
and11component tests passed. Ready recovery also publishes the original public
pin from verified immutable assets when a metadata write was lost. An initial
serialization mismatch was corrected and the lost-metadata case is covered.
The broader HTTP suite was run against an unmigrated base database and failed
unrelated fixture setup (missing organizations/users tables); this does not
count as a passing full HTTP integration run. Linux worker/API/setup builds and
focused Go vet passed. Actual private network/SSH remains a separate live gate.
