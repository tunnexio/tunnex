# Provider configuration persistence — implementation contract

Status: **local implementation authorized**. After the reviewed proposal and pending-decision summary, the user instructed “do next slice development” on 2026-09-24. This authorizes the proposed provider-persistence slice locally. Public create exposure, runtime activation, engine installation, cloud operations and remote publication remain separate. Migration 0158 was verified latest at entry; this slice uses 0159.

## Recommended first increment

Persist the validated `aws-static-ipv4-v1` address/routing profile only when atomically creating a **new**, disabled, never-delivered connection. Keep caller-selected UUID/create-only conflict semantics and verified-human `ipsec:manage`. Reuse existing opt-in, authenticated capability-version/freshness, encryption and audit gates. Community, Trial and paid tiers remain equivalent.

Choose **create-only configuration**, not configuration editing, replacement, attachment to an old identity reservation or PSK rotation. Existing identity-only connections stay readable/deletable and acquire no inferred provider profile. Correcting configuration requires deleting the never-delivered record and creating a new identity. Explicitly show this restriction wherever creation is eventually exposed.

`aws-static-ipv4-v1` identifies the immutable validation/storage shape, **not** a supported engine, approved crypto proposal, negotiated SA or working VPN. Do not persist selectors, algorithms, IKE proposal strings, engine commands, DPD/rekey options or route installation state. A later delivery profile requires its own version and runtime disposition; it cannot silently assign engine meaning to this identifier.

## Additive records and identity

Recommended normalized children, with exact SQL names provisional:

| Record | Fields and purpose |
| --- | --- |
| `ipsec_provider_bindings` | One row per `(connection_id, org_id)`: immutable profile ID `aws-static-ipv4-v1`, configuration revision 1, creation time. Retained with the connection tombstone; contains no addresses or credentials. |
| `ipsec_aws_static_configs` | One live row per binding: customer public outside IPv4. Immutable until terminal deletion. |
| `ipsec_aws_tunnel_configs` | Two live rows keyed by the existing immutable tunnel IDs; org/connection/slot ownership, AWS public outside IPv4, canonical inside `/30`, explicit customer/AWS inside IPv4. Same gateway assignment as the parent, enforced by composite ownership references rather than trusting duplicated request claims. |
| `ipsec_aws_local_prefixes` | 1–64 live rows referencing **exact approved subnet records of the selected Site**; preserve subnet ID, Site ID and exact canonical CIDR. No subnet creation or approval as a side effect. |
| `ipsec_aws_remote_prefixes` | 1–64 live canonical remote IPv4 CIDRs, owned by the connection/org. These rows reserve addresses; they are not shared Site advertisements or policy grants. |

Use PostgreSQL `inet`/`cidr` columns with IPv4, host-mask and profile-bound checks, not opaque JSON configuration. Every child ownership edge includes org and connection; tunnel edges bind the existing slot/identity. Deferred completeness checks require the entire provider shape for a live binding and no address-bearing children after finalization. No partially configured success is representable.

Configuration revision is initially fixed at 1 and separate from desired revision and secret revision. Create begins at desired revision 1 and secret revision 1. Existing PSK envelopes stay in `ipsec_tunnel_secrets`, bound to authoritative org/connection/tunnel/secret revision; no copy in provider rows. Later name-only edits, if separately implemented, must not rebind secrets or alter configuration. Ordinary list/detail DTOs remain credential-free; an eventual authorized configuration view selects nonsecret fields explicitly. No raw row serialization, PSK read/export, secret hash or fingerprint.

Local-prefix ownership recommendation is **exact subnet equality**, not arbitrary subprefix containment. Add a composite uniqueness/FK target covering subnet identity, Site, CIDR and status=`approved`; the provider reference requires that exact tuple. This blocks deletion, reassignment, CIDR mutation or approval withdrawal through both service and raw SQL while referenced. It avoids a containment rule that cannot be enforced by a normal FK. Multiple connections may reference the same approved local subnet if their remote ranges remain disjoint.

## Conflict reservations

Within the gateway's org, reject any live provider tunnel reusing an inside `/30` or AWS outside peer on that assigned gateway. Canonical `/30` equality covers overlap for this profile. Preserve unique reservations even while disabled; creation is configuration reservation, not activation. A customer outside address may be shared by connections behind the same NAT. AWS outside peers may be reused on a different gateway only if all other org-wide range checks pass.

Reserve remote prefixes **org-wide**: no overlap with another live provider connection's remote prefix, any approved Site subnet, organization device pool or Kubernetes VIP range. This deliberately declines multipath/shared-remote-network configurations in v1. Do not count shared policy-resource CIDRs as independent allocated routes: the current routed-range view derives forwarding ownership from Sites, device pool and Kubernetes VIPs; policy rules alone are access descriptions.

Reserve each provider outside address as an underlay host dependency. Neither existing nor later approved Site subnet, resized device pool, Kubernetes VIP range or provider remote prefix may cover a live customer's/AWS outside address. Otherwise a later unrelated range change could invalidate the preflight's no-underlay-route-capture condition. Duplicate outside dependency hosts across records are harmless; dependency-versus-route intersection is the refusal. Inside addresses must remain disjoint from these routable classes as well as gateway-local tunnel assignments.

Pending subnet advertisements are not reservations and may overlap; approval must refuse. Remote-prefix reservation release occurs only in the same transaction as final deletion. AWS virtual-private-gateway-wide inside-CIDR uniqueness across *other systems* cannot be proved from local state without trusted AWS ownership/inventory; this scope checks the local assigned gateway and explicitly does not claim AWS-account-wide validation.

## Existing writers and feasible serialization

Current inspected seams:

- `sites.Service.ApproveSubnet` takes `LockDeviceKey(org.String())` before `subnetguard.Collect`; `devices.Service.ResizePool` and `k8s.Service.registerCluster` use the same advisory key. Its SQL is `pg_advisory_xact_lock(hashtextextended(orgUUIDText, 0))`.
- `subnetsrc.Source` currently collects approved Site subnets, organization device pool and Kubernetes VIP ranges. It has no IPsec reservations. Merely checking the new rows in Create would leave all existing writers able to invalidate them later.
- `sites.Service.RemoveSubnet` currently deletes without the range advisory lock; `AddSubnet` creates pending rows. `RouteLAN` composes advertise/approve and must inherit the same checks. `DeleteSite` has separate agent-access checks and existing IPsec assignment FKs, not a provider-subnet ownership check.
- `sites.sql` exposes raw approval/deletion queries; `organizations.sql:UpdateOrgPoolCidr` and `k8s.sql:CreateK8sCluster` are the underlying range writers. Existing FK/raw-SQL tests therefore remain necessary in addition to HTTP tests.

Recommended common application lock order for transactions touching provider reservations or allocatable ranges:

1. Existing **org range advisory key first**; never acquire it after holding the org row.
2. Live organization row, then existing IPsec setting when applicable.
3. Selected Site and referenced subnet rows in stable UUID order; assigned gateway; connection; tunnel slots.

This explicitly extends the earlier IPsec-only order. The advisory-first rule avoids inversion with pool resize, which already takes the range key before updating the org row. Existing opt-in/identity-only operations need not acquire the range key if they never wait on it. Every provider-create/finalize operation must use this order. Existing approval, pool-resize and cluster-register paths must lock/version the org before dependent row mutation; removal paths must do so before deleting protected subnet rows. Re-read approval/ownership after acquiring locks; do not carry a pre-lock `GetSiteSubnetForOrg` result into admission.

Extend the **shared** collector/checker with typed IPsec remote, inside and underlay-host classes so every existing allocation writer sees reservations. Provider admission must also check remote routes against the collected ranges. Use explicit candidate-class rules: an underlay dependency is not an allocated LAN, repeated dependency hosts are allowed, and exact selected local subnet references must not collide with themselves. Do not filter arbitrary equal CIDRs out of the shared validator to make a request pass.

Database boundary: composite FKs enforce local approval/ownership and parent assignments; uniqueness enforces gateway inside/peer equality. Cross-table overlap still needs transactional guards because no existing single-table exclusion constraint covers these classes. Propose mirrored database trigger checks on provider reservation writes, approved subnet changes, org pool changes and cluster VIP changes. New mirrored refusals apply only to conflicts involving a live provider reservation or reference; they must not introduce a new validator for pre-existing WireGuard-only combinations. Preserve previous WireGuard-only acceptance/refusal behavior and allow pending advertisements; provider conflict checks apply when an advertisement becomes approved, not when it is merely added. They acquire the same advisory serialization and **version a stable per-org row** before range reads, including the first-provider-record case. The organization row already used by the IPsec foundation is the recommended anchor; its existing timestamp trigger means these guarded range changes also update `organizations.updated_at`. This visible timestamp effect is part of the requested disposition, not an accidental implementation detail.

Why version as well as lock: an older Repeatable Read snapshot can miss a newly committed reservation after waiting on an advisory lock. Updating the stable row forces serialization refusal rather than admitting a stale conflict set. Raw SQL may already hold a subnet/cluster tuple lock before its trigger reaches the advisory/org locks; an opposing service transaction can deadlock. PostgreSQL must abort one transaction safely; do not claim raw SQL has the application's lock ordering or blindly retry unvalidated writes. Guard errors/serialization/deadlock handling must preserve atomicity and expose a scoped conflict/retry result, never a successful partial change. No new extension is assumed; a central cross-resource allocation ledger is an alternative below.

This is intentionally more than a new configuration table. **Do not ship provider creation until every opposing mutation seam and raw-SQL boundary is implemented and proven.** No range checks are inferred from a count or from the pure validator.

## Deletion, audit and rollback

Delete still requires exact desired-revision CAS and verified-human management authority. In the never-delivered schema, use this order inside one locked transaction:

1. Remove provider ownership/address rows, remote/underlay reservations, exact local-subnet references and provider tunnel-configuration children **before** updating the parent to terminal intent and null live Site/gateway references. Otherwise composite references to the parent assignment can block the terminal update.
2. Advance the parent to terminal deleted with the exact desired-revision successor; release live Site/gateway references and record finalization timestamps.
3. Remove the existing 0158 sealed-secret rows and then the existing tunnel rows **after** the parent is terminal. The current 0158 child lifecycle trigger deliberately refuses their earlier deletion.
4. Append the redacted audit and commit.

New provider-child delete guards allow withdrawal only as part of this terminal-finalization transaction: deferred completeness/lifecycle checks must reject a commit that removed or replaced provider children while leaving the parent disabled. Configuration is immutable otherwise; this ordering is not an edit API or a general child-deletion permission. Intermediate states are uncommitted, and every failure restores the original complete configuration and reservations.

Keep connection identity/history, last desired revision and the immutable provider binding `(profile, configuration_revision)` with the tombstone. Existing WireGuard Sites, subnets, gateways and policies are not deleted or modified. An audit/FK/child failure restores all configuration, secrets and reservations.

Future delivered states cannot use this immediate finalizer: reservations/ownership must survive until exact acknowledged cleanup. No timeout or revocation releases them. That future lifecycle remains out of this increment.

Migration down refuses if **any provider binding, including a tombstone, exists**, before destructive DDL. Empty provider-schema rollback is supported while preserving existing 0158 records. No backfill of identity-only connections, no destructive data conversion, no automatic downgrade or cleanup sweeper.

## Alternatives and local disposition

**Recommended:** create-only normalized profile, exact approved-local-subnet references, org-exclusive remote routes, gateway inside/peer uniqueness, underlay dependency reservations, shared range-lock/collector integration and database guard/versioning above. This has a broader concurrency change but a concrete enforceable boundary.

**Defer persistence:** keep pure/API preflight and redacted identity storage until runtime decisions are ready. Safest smaller increment, but still no stored provider configuration.

**Central allocation ledger:** migrate all Site/pool/Kubernetes/provider ownership into one typed reservation model, potentially enabling an exclusion constraint. This is a substantially larger migration/backfill and not recommended for this slice; it needs separate compatibility and rollback design.

Local disposition on 2026-09-24: implement the recommended provider scope/subset; create-only correction workflow; local exact-subnet and org-wide exclusive-remote ownership; underlay/inside reservations; the common lock-order and raw-SQL/versioning changes (including org timestamp effect); retained provider tombstone metadata; populated rollback refusal. Fixed algorithms/selectors, NAT runtime identity, installation and activation remain unapproved and are not bundled into this decision.

## Required evidence before exposure

Write regressions before migration/service changes. Prove cardinality/ownership through direct SQL; complete synthetic configuration plus two sealed PSKs; stale/repeated identities; rollback at each child/encryption/audit stage; exact-subnet deletion/status/CIDR refusal; create versus subnet approval/removal, pool resize, cluster registration, opt-out/revocation and another conflicting provider create. Observe blocked PostgreSQL sessions rather than timing sleeps. Test both winning orders and Read Committed/older Repeatable Read snapshots. Prove disabled deletion releases only owned reservations and preserves original shared objects. Mutate each ownership/overlap/versioning guard independently and require behavioral failures. Preserve existing WireGuard-only tests and unchanged success/failure behavior except the explicitly approved timestamp consequence.

Only after these gates, deterministic generated queries/types, independent review and a separate public API contract should provider create become callable. Runtime support and packet-path qualification remain separate.

## Implemented storage mechanics

Migration 0159 uses the normalized names above. The parent carries an immutable nullable `provider_profile` marker, set only when creating a new provider-backed identity. An existing identity-only connection cannot acquire the profile later. The retained binding has monotonic internal `configuration_sealed` and `withdrawal_started` flags: deferred completeness seals a complete configuration, preventing later append operations; first child withdrawal requires terminal finalization and prevents delete/reinsert edits. These enforce the create-only contract without transaction-ID heuristics or a new public lifecycle.

`CreateProviderDisabled` is internal, reusing the existing opt-in, authenticated gateway capability/freshness, envelope and audit checks. It locks exact approved subnets and uses the shared typed reservation collector. Internal `ReadProvider` explicitly selects only nonsecret configuration under a consistent snapshot. Ordinary HTTP connection responses remain unchanged. Delete removes only provider-owned dependencies before terminal parent update, then the existing tunnels/secrets; audit failure rolls the complete transaction back.

Mirrors include Site organization changes as well as subnet, pool and Kubernetes range changes. Subnet admission rechecks Site ownership after locks, closing the race with a concurrently moved Site. Stable organization versioning handles old Repeatable Read snapshots; existing WireGuard no-ops remain no-ops. Mirror locking allows existing cleanup of soft-deleted/deleting organizations, while provider creation retains its separate live-organization gate.

Profile predicates also enforce the reviewed public IPv4 and routed-prefix bounds at the database boundary. Gateway-local inside/peer uniqueness permits reuse on another gateway with disjoint remote ranges. Underlay hosts may be shared, but cannot be captured by allocated routes. No public provider-create endpoint, agent delivery or runtime activation is added.

## Local qualification — 2026-09-24

Regressions preceded implementation (`/private/tmp/s2s-provider-schema-red.log`, `/private/tmp/s2s-provider-service-red.log`, `/private/tmp/s2s-shared-provider-red.log`). All PostgreSQL gates used verified tmpfs project `tunnexs2sfoundation0924` and uniquely named disposable test databases.

Final race gate passes: schema tests 52.379s and provider service tests 29.570s (`/private/tmp/s2s-provider-final-race.log`). Evidence includes complete stored configuration/nonsecret reads, exact ownership, forbidden edits/append/profile attachment, bounds, atomic child/audit failure rollback, gateway-local reuse versus org-wide remote conflict, tombstones, populated rollback refusal and identity-only records preserved across 159 down/up. Twelve observed-lock cases cover Site/pool/VIP conflicts in both winning orders at Read Committed and Repeatable Read; another observed-lock case verifies admission after Site organization movement. Actual service races cover competing Site approval/removal, pool growth, Kubernetes registration, opt-out and revocation. WireGuard no-op timestamps and soft-deleted/audit-free cleanup paths remain intact.

Six migration guard mutations (local ownership FK, completeness, child immutability, mirrored overlap, organization versioning, sealed append prevention) failed behaviorally and the original migration was restored exactly before final tests (`/private/tmp/s2s-provider-schema-mutations.log`). Independent schema/service/shared-writer reviews found no remaining actionable issue.

Legacy identity/settings/connection regression passes at schema159 (`/private/tmp/s2s-provider-identity-regression.log`). HTTP and resource-guard race gates pass (`/private/tmp/s2s-provider-http-guard-race.log`). Shared collector/conflict race tests pass; SQLC v1.31.1 generation is identical across two runs (`/private/tmp/s2s-provider-sqlc-final.json`). Open and enterprise API builds pass (`/private/tmp/s2s-provider-build-open.log`, `/private/tmp/s2s-provider-build-enterprise.log`). No web styling or browser interaction changed in this slice.

The guarded local review CP `tunnexs2scp0924` was migrated to **159, dirty=false**, and its owned API process refreshed from the tested build. API health, Vite API proxy and `/site-to-site` return 200 (`/private/tmp/s2s-provider-local-smoke.log`). No provider configuration was seeded in the review CP. Positive capability and traffic-independent configuration tests remain synthetic; production agents still advertise unsupported version0. No live tunnel, activation, installation, cloud change, commit or push is claimed.
