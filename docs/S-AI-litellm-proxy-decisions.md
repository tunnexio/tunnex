# Actual LiteLLM OSS proxy backend

## User-directed change

The user explicitly requests the actual LiteLLM model-call proxy, beyond the
existing SDK test bridge and visual resemblance. This supersedes the prior
recommendation to retain Bifrost as the sole engine for new functionality.

## Locked implementation-independent preparation

Prepare a separately pinned full LiteLLM1.100.0 OSS proxy runtime, including its
proxy extras, private service configuration and independent PostgreSQL storage.
Do not replace the running Bifrost URL or mutate existing provider/usage data.
The runtime requires a stable independent salt/encryption secret, a separate
rotatable administrative secret, prompt-free accounting, and no public master-key
administration. Existing SDK preflight remains independently available.

Remove the duplicate Approved upstream endpoint chooser from the current form;
keep the typed Upstream API Base and exact server-owned allowlist validation.
This is a UI simplification, not removal of the approved egress boundary.

## Integration contract proposed for disposition

Recommend per-organization opt-in migration with explicit backend identity on
credentials, deployments, virtual-key bindings and retained usage attribution.
Use actual OSS /credentials, /model/new and scoped /key APIs; keep management
private behind Tunnex RBAC. No embedded global admin dashboard or master key in
tenant browsers. Community isolation must not rely on premium model_info.team_id.

Map public model names to unique internal aliases bound to organization,
credential and exact upstream model. LiteLLM empty virtual-key models means ALL;
zero scope must have no active key or explicit blocked=true with exact readback.
Persist/seal a new virtual-key token before native registration for idempotent
recovery; do not generate orphan active keys after uncertain writes.

Existing Bifrost provider secrets are masked by supported read APIs. Preserve
old traffic/history until the operator rebinds credentials from an existing
secure source or re-enters them. Do not read encrypted native DB material or add
a reveal-key API. Recommend re-entry rather than an offline secret-export tool.
Cutover prepares new credentials/deployments/blocked keys, verifies persisted and
active state, holds new admission for that scope, disables old keys, activates
new binding, then resumes. Accepted old streams keep their bounded lifetime.
Rollback retains old data and never replays uncertain inference automatically.

Aggregate old and new usage for daily soft thresholds. Missing accounting or
unknown monetary prices must not become free usage. Additional modes require
mode-aware request/response bounds and units; asynchronous video needs tenant-owned
job IDs and read authorization, as recorded in S-AI-credential-modes-decisions.md.

Per-org cutover, credential re-entry, scoped deployment naming and dual-ledger
attribution are material state/security choices still requiring disposition
before schema or engine admission changes. Runtime packaging and the authorized
UI simplification can be completed independently. No cloud action, existing-stack
restart, secret migration, engine cutover, merge or release is implied.

## Verified distribution constraint

Released litellm1.100.0 proxy-extra metadata requires litellm-enterprise0.1.62.
The exact enterprise wheel (SHA256
337697160896d52079290ffe8051c3dee450653d271cb29723af6db8546eb7d9)
contains dist-info/licenses/LICENSE.md requiring a valid BerriAI enterprise
license for production and restricting redistribution. It cannot be bundled as
Community OSS merely because enterprise endpoints are unused.

Use the MIT base LiteLLM proxy code with an explicit OSS server dependency set,
omitting the optional enterprise distribution. Upstream optional-import/error
behavior and license checks remain intact. Verify actual server import/startup
with that set. Do not claim parity with licensed upstream enterprise features.
