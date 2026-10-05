# Sandbox runner enrollment backend

The runner setup UI uses real enrollment and the existing bounded remote worker.
This slice supplies its public contract and durable authorization, not live
installation or deployment. Parent integration owns OpenAPI, HTTP/RBAC generation,
main wiring, machine installer, UI, distribution and the native qualification trial.

## Locked decisions

- Enrollment is explicit, verified human administration of the configured
  organization and profile. `sandbox:runner_manage` belongs to owner/admin.
  Current database membership is authoritative; machine principals cannot enroll.
- Installing a runner precedes enabling sandbox creation. Enrollment requires
  the module and enforcing policy, but does not enable `sandboxes_enabled`.
  Ordinary execution retains the creator's existing authorization and policy.
- The deployment supplies one immutable organization/profile/controller/image
  envelope. The first supported native host is Ubuntu 26.04 AMD64, explicitly
  advertised by the profile. The packaged installer supports 64 workload PIDs,
  128 MiB, one CPU, one retained slot and at most 900 seconds from Create.
  ARM64 remains compilation only. No unrelated owner privileges are conferred.
- A 32-byte random secret authorizes a ten-minute challenge. Only its SHA256 is
  stored. Idempotency replays metadata without recovering the secret; a lost
  secret requires cancel/new enrollment. Tokens never enter install commands,
  URLs, public profiles, audit metadata or distribution artifacts.
- Machine TLS and probe private keys are generated on the machine. CP accepts
  a signed Ed25519 CSR without identity extensions and issues only the configured
  runner URI. No browser response includes private key material.
- Atomic redemption pins the CSR SPKI, canonical public SSH probe and immutable
  binding. An exact retry during the original challenge returns the same public
  certificate; changed keys conflict and retry never extends authority.
  Active renewal revalidates current standing and keeps the same key. Renewal
  caching is keyed by SPKI, preventing old enrollment key reuse.
- Creation or certificate issuance cannot imply Ready. Health must be an actual
  current authenticated ping matching the full binding and stored probe, fresh
  within 45 seconds. New hosts need exact supported-platform reports, independent
  CP native-trial proof and audited human CAS review. A missing proof hook denies
  approval and Ready even if every host-reported check says passed. Reports are
  evidence supplied by a machine, not independent native measurements.
- Qualification reports bind enrollment, SPKI, source, profile, images and runtime
  fingerprint. Missing, failed, unrun or unsupported checks cannot be approved.
  Evidence and completed review are immutable. A subsequent failed report removes
  qualification; a static reviewed SPKI preset preserves existing installations
  only while any newer report is compatible and successful.
- The separately owned trial validator may admit only an exact durable admin
  qualification workload under normal ownership, terminal, policy, TTL and slot
  constraints. A nil hook grants no unqualified execution. There is no generic
  bypass for ordinary Create or start.
- Revoke atomically requests deletion and increments generation only for mapped
  retained workloads, revokes their runtime credentials and blocks their peers.
  Confirmed provider/network cleanup and worker retirement still release capacity.
  A revoked, still-valid certificate permits only exact desired-deleted cleanup
  operations for its mapped workload. It cannot renew, probe, materialize, enroll
  or start. Cleanup authority ends at frozen certificate expiry or retirement.
  Offline execution remains bounded by the original local 900-second TTL.
- Replacement is blocked by any retained sandbox in the organization, including
  old configuration profiles and instances awaiting first command authorization.
  Enrollment, workload binding and qualification evidence cannot be reassigned.
- The supported public distribution loader verifies source/edition/architecture,
  duplicate fields, bounded regular files and HTTPS pins. It updates only public
  script/bundle/source pins; it cannot change gateway, CA, images, policy, identity
  or native qualification. Image descriptors and deployment/catalog setup remain
  separate explicitly reviewed inputs in parent integration.

## Public image delivery follow-on

`RunnerEnrollmentConfig.DistributionFile` names the bounded public distribution
manifest. Its optional `workload_image_delivery` URL/hash is present exactly when
`workload_images_built` is true; native qualification remains false. The separate
`WorkloadImageDeliveryFile` names downloaded public descriptor bytes whose hash
must match that manifest pin. `LoadRunnerWorkloadImageDeliveryConfig` verifies
source, Linux AMD64, dependency/base/config digests, bounded archive metadata and
the no-service/no-per-launch-install flags. It derives the release archive URL
and fills URL/hash only for an already reviewed matching image config identity.
It creates no template and cannot turn artifact production into host qualification.
Deployment wiring loads distribution, then image delivery, then validates the
complete immutable runner config. No Go source editing is required to consume
these published artifacts.

## Validation and remaining integration

Focused PostgreSQL and CSR race checks run in both API editions with disposable
synthetic databases. They cover current membership and principal type, concurrent
idempotency, secret hygiene, exact redemption retry, expiry, supported platform,
proof-plus-human qualification gates, immutable binding, revocation, cleanup-only
effects, retained-slot replacement and migration 195→196/owned rollback preserving
published App Access authority. Distribution fixtures verify fail-closed pin loading.

These tests are substitutes for the new-host native trial, not a native qualification.
Parent must combine the runtime callbacks, generated HTTP contract, UI, published
artifacts and separately owned trial proof. No live enrollment, infrastructure,
deployment, external publication or performance result is claimed by this slice.
