# Runner enrollment from the dashboard

The user added runner-machine enrollment and end-to-end UX to the PR scope on
2026-10-05. The previously validated source checkpoint remains preserved; it
does not complete this new flow. Local implementation and synthetic QA are
authorized. No real enrollment or host activation is authorized. Draft publication is conditional on completing the agreed source flow and checks; merging and deployment remain outside this session.

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
helper. The reproducible Ubuntu dependency base, archive producer and existing CI artifact path are implemented. Fresh configuration uses the offline profile generator; the controlled trial prepares its disabled template.
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

## Implemented flow and remaining validation

The deployment plan now has typed public bundle/image/source/controller/gateway
pins. Machine-local CSR/probe generation and the actual installer path are
implemented at `f598e66`; verified public script/distribution packaging is
implemented at `3b23f99`. Backend authority, current-key broker fences, authenticated health, the dashboard wizard and the controlled qualification service are integrated. Machine installation refuses unsupported hosts before downloading or redeeming a token. The trial uses canonical sandbox lifecycle state and confirmed retirement; the actual Python report producer is exercised against the control-plane review service with synthetic fixtures. Native qualification is not claimed by these tests.

Review identified two product gaps that a blocker-only wizard would not close:
the reproducible Ubuntu dependency/image delivery path, and native qualification
of a newly enrolled host. The image story now supplies a signed dependency lock, offline workload archive and public source/hash descriptor through the existing artifact path. Its verified source archive is 68.1 MiB, with 186.2 MiB of unpacked layers; these build measurements do not qualify a host. The implemented controlled qualification trial uses the same
policy, terminal identity, retained slot, resource and original lifetime bounds;
ordinary Create stays blocked until reviewed qualification and fresh health.
Host reports alone cannot prove private SSH, offline expiry or confirmed cleanup.
The admin review API therefore fails closed without independent canonical proof.

These are implementation dependencies, not selection requirements inferred from
an unspecified control. No automatic capacity expansion, cloud provider, heavy
dependency stack or hosted AI agent is introduced.


Ordinary creation checks fresh runtime readiness and atomically binds the current
runner grant within the existing organization transaction. Revocation before
commit rolls creation back; revocation after commit can find the assignment
before any runtime command and request its bounded cleanup. Neither outcome
claims physical deletion before provider and network retirement are confirmed.

Legacy qualified runtimes use their existing canonical readiness status. Enrolled
runtimes explicitly advertise the enrollment requirement. Setup refresh retains
the open wizard through the Ready transition while refusing activation on stale
or failed reads. Creation still includes template selection, an owned terminal,
saved public SSH keys and configurable optional Skills. Existing local keys are
used by the SSH client; no private key is uploaded.


## Source completion checkpoint

The agreed API, issuer/runtime integration, machine installer, reproducible
image delivery, controlled trial and dashboard journey are implemented. Both
editions passed fresh database qualification; the enterprise full sandbox
package and open affected downgrade proof passed. All initially failed
completed-case tests and the two enterprise race cases passed their bounded
retests. The original concurrent full-run failures remain recorded in the
[validation summary](S-sandbox-pr-validation.md).

Final browser QA passed 39 desktop/narrow checks with 34 screenshots, including
legacy enrollment compatibility, Ready dialog retention, authoritative token
invalidation, delayed review races and the Skills/public-key/terminal/SSH flow.
Exact-source artifacts and remote required CI accompany draft review. Native
host qualification, performance benchmarking and the separately requested live
SCP check remain distinct follow-up gates. No live target was activated here.
