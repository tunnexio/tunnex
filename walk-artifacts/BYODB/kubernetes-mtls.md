# Kubernetes BYODB mTLS runtime proof — 2026-09-06

## Subject and boundary

Actual `helm install` and `helm upgrade` of the repository's `tunnex-cp`
chart against a fresh local kind cluster, not a render-only substitute.
Cluster: `tunnex-byodb-mtls-20260906`; namespace/release: `byodb`.
kind v0.33.0 / Kubernetes v1.37.0 / native Linux ARM64.
No AWS, Azure, existing Kubernetes context, default Compose project or unrelated
container was changed. PostgreSQL and Redis were reachable through ClusterIP
services only; no database host port or public endpoint was created.

API/migration source corresponds to content commit
`d688aac8e0d60c4f07ed28cfadee1cb2ab810b04`; the working chart additionally included
the pending startup probe (5-second interval, 180 failures). The locally built API
image included the pending 900-second Docker startup grace. This is not evidence
of exact-final-SHA CI, a signed production release, or a public installer walk.

Native local image identifiers:

- `tunnex-mtls-api:20260906`:
  `sha256:c51fdb33d5421afd79a2a46a5fb442395b2d59add26efb9f7631ed3b27f25afa`
- `tunnex-mtls-migrate:20260906`:
  `sha256:ba25b9247710f42030583ecd5667d782b34023d9d24cef665d3f32f516d9ddb9`

## Configuration under test

- Dedicated PostgreSQL 18 fixture, separate from chart-managed resources.
- Server `hostssl` policy requires a CA-verified client certificate plus SCRAM
  authentication; plaintext host connections reject.
- Both URLs specify `sslmode=verify-full`, the CA/client certificate/key paths,
  and `channel_binding=require`.
- Runtime URL is an existing Secret with custom key `connection`.
- Migration URL is a separate existing Secret with custom key `ddl-connection`.
- Both chart workloads mount the existing TLS Secret read-only.
- Separate `migrator` and `runtime` roles; neither is superuser, database creator
  or role creator. Runtime receives object access through migration-role default
  privileges, not role membership or schema ownership.
- Pre-created master-key Secret. Chart creates no master key or database.
- API replicas 1; web and edge replicas 0; agent Service ClusterIP. This focused
  proof does not qualify browser ingress, gateway connectivity or Kubernetes HA.

## Live results

1. Fresh `helm install byodb ... --wait` succeeded. The actual pre-install
   migration hook completed and was removed by its normal success policy.
2. Schema readback: `136|f` (version 136, not dirty).
3. Public table ownership readback: `migrator|128`.
4. Runtime `CREATE` privilege on schema `public`: `f`.
5. API deployment reached 1/1 Ready with zero restarts. In-pod `/healthz`
   returned `service=tunnex-api, status=ok`.
6. PostgreSQL session readback for the actual API connections:
   `runtime|t|TLSv1.3|/CN=byodb-fixture-client`. This confirms server-observed TLS
   and client certificate use, beyond URL configuration alone.
7. Negative case used the actual chart migration Job template with a different
   existing URL Secret and CA-only TLS Secret, omitting the client certificate
   and key. It failed with one failed pod and the redacted message:
   `database_preflight_failed: database_auth_failed: check the database role and credential`.
   The positive API remained Ready; no credentials appeared in the diagnostic.
8. Actual `helm upgrade byodb ... --wait` reran the migration hook successfully;
   release revision 2 is `deployed`, schema remains `136|f`, and API health is OK.

## Retention and remaining limits

### Final-code requalification

Rebuilt native ARM64 API and migration images from HEAD
`4616135fc2c49d3c80033129d2856096038bf61b` plus the pending effective native-backup
TLS/default and explicit-URL-presence fix. At build time the modified
`apps/api/internal/dbcheck/check.go` SHA-256 was
`445b84fab7247ab4f166f00c32e77ad49e7be84122f432e0087880895a4f9aa2`.
The final commit annotation is to follow; this records the tested working content
without inventing an exact-final-SHA claim.

- `tunnex-mtls-api:20260906-final`:
  `sha256:566801032f87850a4a72f6f1aac5f06278a8f66ed6c4f868f49423344de67eb9`
- `tunnex-mtls-migrate:20260906-final`:
  `sha256:27fc96a0f36e7acc5d1c8b066940bbd66a8f6b0c6dae5e3e98ac15a4098bd479`

Loaded both images into the same isolated cluster and performed another actual
Helm upgrade, overriding only the image tag. Release revision 3 is deployed.
The migration hook completed, schema remains `136|f`, and the replacement API
is 1/1 Ready with zero restarts and `/healthz` status `ok`. PostgreSQL again
observed `runtime|t|TLSv1.3|/CN=byodb-fixture-client`.

Repeated the missing-client-certificate chart Job with the final migration image:
one failed pod, the same redacted `database_auth_failed` diagnostic, and no
impact on the healthy API. No existing Secret was edited.

Also ran the final API's actual `preflight --database-dump` and
`--database-verify-archive` inside Kubernetes using the runtime role and mounted
mTLS files. Both succeeded; the custom-format dump was 815,571 bytes, retained
outside Git with mode 0600. This adds native-client backup coverage on the
final mTLS path; it does not claim a new restore drill.

### Operator-driven credential rotation and reconnect

On the same isolated fixture, rotated only the `runtime` PostgreSQL role password,
updated its existing `runtime-url` Secret using the existing custom `connection`
key, and explicitly ran `kubectl rollout restart deployment/api`. Migration-role
credentials, CA/client certificates, master key and database contents were not
changed. Old and new recovery URL files were retained outside Git with mode 0600;
no password was printed or placed in command arguments.

The replacement API reached 1/1 Ready with zero restarts, `/healthz` returned
`status=ok`, schema remained `136|f`, and fresh PostgreSQL sessions again reported
`runtime|t|TLSv1.3|/CN=byodb-fixture-client`. A fresh connection using the old
credential was rejected with the redacted `database_auth_failed` diagnostic.

This proves the documented **manual/operator-driven** credential rotation and
reconnect procedure. It does not claim automatic Secret watching, live pool
credential refresh, password provisioning, or zero-downtime rotation.

The isolated kind cluster and failed negative Job are retained for inspection;
there was no cleanup. Fixture certificates, private keys, URL files, master key
and kubeconfig remain outside Git in a mode-0700 temporary directory; kubeconfig
is mode 0600. None is included in this evidence.

This satisfies the focused Kubernetes BYODB mTLS migration/runtime/custom-Secret
and separate-role wire proof. It does not claim automatic credential rotation,
cloud-managed Kubernetes qualification, a signed installer/upgrade release,
multi-node failover, or a PostgreSQL major upgrade. The positive TLS test matrix
and negative authentication-downgrade matrix are separate evidence.
