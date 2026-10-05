# Enrolled runner runtime boundary

This source slice composes dashboard enrollment with the existing bounded remote
worker. It does not qualify a native host, activate a live runner or change the
single retained workload limit.

`APIWorkerConfig.Enrollment` is explicit and requires a remote, organization
binding, an empty static probe key and no initial-create intent. Legacy static
configuration still requires its original public probe. `Client()` cannot bypass
the enrollment authority; the enrolled path uses `EnrollmentClient(authority)`.
`LoadRemoteWorkerIssuer` supplies the configured scoped issuer to the service.

Every poll, reply and renewal rechecks the verified certificate against current
durable enrollment authority. The broker checks its configured URI and checks
certificate expiry again on established TLS connections. Commands receive a
second durable ownership/state check both when delivered and when receipted.
Rejected late receipts never complete an outstanding effect.

Revoked or invalid grants can retain cleanup access only for their exact retained
workload, generation and desired-deleted intent. They cannot use health or renewal
lanes. The enrollment service owns the operation allowlist and immutable identity
checks. Cleanup may preserve the original inert lease and advance its generation;
it cannot create a new workload lifetime or extend the original TTL. Physical
provider/network absence and worker retirement still use the existing confirmed
cleanup sequence. A database revocation does not prove immediate SSH closure.
Offline actors retain their original bounded expiry fence.

The RPC client resolves public probe identity from the control plane and
synchronizes snapshots. A health reply must match the full configured binding
and that public key. `RecordHealth` records connectivity, while `RuntimeReady`
separately decides whether trusted qualification is sufficient. An unqualified
host cannot become ready merely by answering its own health probe.

The orchestrator sweeps invalid enrollment authority before dispatch. It attempts
an actual health check at most every five seconds with a three-second deadline,
including when there are no workloads. Cleanup-only credentials skip health;
offline or unqualified health failures do not block cleanup dispatch. Before
initial launch or resume it refreshes the immutable probe snapshot used by the
existing coordinator. Enrollment replacement remains forbidden until the
retained workload is confirmed retired. A missing public identity blocks launch;
the static constructor's missing-key rejection remains intact.

The machine client refuses effects and cached receipts after certificate expiry
and bounds each effect context by the earlier command or certificate deadline.
This adds no execution privilege, TTL extension or renewal during cleanup.

The private mTLS controller accepts qualification reports through a separate
16 KiB POST boundary. It requires current active certificate authority, strict
typed JSON and version validation, and refuses cleanup-only credentials. A 204
means only that a scoped public report was stored. Human review and independently
verified native proof remain separate requirements.

Validation uses synthetic identities and temporary local fixtures: six new
configuration/probe/orchestrator/report tests, four certificate/revocation/upload
broker tests and one client certificate-deadline test. Focused sandbox tests pass with the race
detector in both editions; the full runner transport package passes with the race
detector. Native network, containment, offline expiry and performance qualification
are separate evidence requirements and were not run by this slice.
