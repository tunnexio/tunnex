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

The isolated kind cluster and failed negative Job are retained for inspection;
there was no cleanup. Fixture certificates, private keys, URL files, master key
and kubeconfig remain outside Git in a mode-0700 temporary directory; kubeconfig
is mode 0600. None is included in this evidence.

This satisfies the focused Kubernetes BYODB mTLS migration/runtime/custom-Secret
and separate-role wire proof. It does not claim automatic credential rotation,
cloud-managed Kubernetes qualification, a signed installer/upgrade release,
multi-node failover, or a PostgreSQL major upgrade. The positive TLS test matrix
and negative authentication-downgrade matrix are separate evidence.
