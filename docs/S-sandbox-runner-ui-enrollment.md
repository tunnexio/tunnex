# Runner enrollment from the dashboard

The user added runner-machine enrollment and end-to-end UX to the PR scope on
2026-10-05. The previously validated source checkpoint remains preserved; it
does not complete this new flow. Local implementation and synthetic QA are
authorized. No real enrollment, host activation or publication is authorized.

## Architecture and boundaries

An organization administrator starts an enrollment from Sandbox Setup, selects
an approved deployment profile and sees the host prerequisites. A short-lived,
single-use bootstrap authorizes only that enrollment and bounded runner slot.
The database stores its hash. Tokens stay out of command arguments, environment,
URLs, logs and persisted browser state. The UI presents a copyable command with
public identifiers and a separate one-time secret for terminal stdin.

The host generates its private runner and probe keys locally. It submits a CSR
over verified HTTPS and receives only a signed leaf, public trust material and
the approved configuration. The control-plane CA key never leaves the issuer.
Issued certificates must bind the exact admitted public key and enrollment;
the existing runner URI alone cannot authorize a replacement machine.

The machine flow must call the real verified bundle/image installer and connect
to the existing mTLS transport. It must preserve immutable org/gateway/profile
pins, one shared retained workload, cgroup/resource/absolute-expiry bounds and
confirmed cleanup. Host-admin consent is required for installation/activation.
Connected status comes from authenticated fresh control traffic; Ready also
requires exact binding, capability, image and native qualification checks.
Offline/revoked/expired states cannot silently admit a new workload.

Deployment prerequisites remain explicit: a configured controller issuer and
private listener, approved public binary bundle and immutable qualified Ubuntu
image/archive, and a compatible co-located gateway for the current namespace
helper. The reproducible Ubuntu dependency base/CI input is still missing.
The UI must explain unavailable prerequisites and refuse unsupported hosts;
it cannot qualify an arbitrary machine or operate an IP address by itself.

## Stories and acceptance criteria

1. Define the enrollment contract and authority. Admin-only creation/read/cancel,
   org-scoped records, idempotent intent, short expiry, single-use redemption,
   key-bound retry, revocation and current-member checks have tests. No private
   credential is returned by an admin read endpoint or recorded in audit data.
2. Connect the machine flow. Local key generation, CSR signing, verified public
   package/image/configuration and the existing installer lead to real mTLS
   connection. Unsupported OS/architecture, changed pins, unsafe paths,
   unavailable qualification and malformed/replayed tokens fail closed.
3. Add the dashboard wizard. Prerequisites, install command, one-time secret,
   progress, cancellation, expiry, retry, offline and actionable error states
   use generated APIs. No mock response or timeout alone can render Ready.
4. Validate the complete journey. Enrollment through runner readiness, creation
   with terminal/Skills/public-key selection, connection instructions and
   expiry/delete are exercised with owned synthetic fixtures and local browser
   QA. Existing disabled/draining modules and historical fixed bindings remain
   compatible. Packaging and required CI cover the new public source/assets.

The backend contract precedes machine and UI integration; those can proceed in
parallel after its fields and trust boundaries are agreed. Final generated
contracts, both-edition API tests, UI tests/types/build, artifact verification
and clean source-coverage records follow the integration. Native host/image
qualification remains a separate release gate and must not be claimed by this
source-only work.

## Decisions still being verified

The exact deployment-profile schema, controller issuer integration, public
artifact delivery, probe-key update and broker certificate-revocation seams
are under source review. These are implementation dependencies, not user
requirements inferred from an unspecified selection control. No automatic
capacity expansion, cloud provider, heavy dependency stack or hosted AI agent
is introduced.
