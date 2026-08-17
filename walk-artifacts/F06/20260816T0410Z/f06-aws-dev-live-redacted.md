# F06 AWS DEV live acceptance — redacted

Status: **PASS**

## Provenance and rollback

- Source/branch: `story/F06-agent-ownership-rbac` at `8c3fed8`.
- API: `tunnex-api:f06-8c3fed8-amd64`, image
  `sha256:8ee16ede8aadcb0db7f0baf9735b1ec60ad3083d27b972434eab8f3de6a6f34f`.
- Web: `tunnex-web:f06-8c3fed8-amd64`, image
  `sha256:1398631acbbf5a01a6373e133f626aba169e34cd969322d58674e317ef5e0275`.
- API, web, nginx, node, PostgreSQL, and Redis were healthy; API/web/nginx
  restart counts were zero at completion.
- Schema migrated `94 -> 95`; final ledger was `95`, `dirty=false`.
- `/home/ubuntu/f06-rollback-8c3fed8/SHA256SUMS` verified after the walk.
  The bundle includes the pre-walk schema-94 dump, image IDs, compose inputs,
  and deployment inventory. No credential value is recorded here.

## Disposable identities

- Organization: `019fe7d9-4e82-7a28-b579-9f53bc711643` (AWS DEV only).
- Agent: `01a008c4-5312-7207-8a00-f505cb65eb38`,
  `f06-rbac-live-20260816T0410Z`.
- Accountable/member principal: `01a003f0-3bfc-7ebc-b867-52832b42d929`.
- Managing group: `01a008c7-4faa-75c3-92e5-6c863f0302b5`.
- Agent-source rule: `01a008ca-dd96-7eca-96d7-101ca7a79d45`.
- Lifecycle group: `01a008cd-8439-7655-9d58-b2d5a99cbb8a`.

Bootstrap used a client-generated WireGuard private key. Only its public key
left the agent VM. The one-time token, bootstrap response, runtime credential,
private key, and configuration body never entered logs or this artifact and
were removed during cleanup.

## Live wire and assignment invariants

- Pending agent approval returned `204`; profile became `active`.
- Released `/agents` rendered the exact agent as `connected`, gateway
  `aws-gw-1`, with non-zero traffic.
- Baseline config SHA-256 was
  `fe84ceaf84c57898986a3501cb5ab76ad02928e1bbd5e6b73458a367d86acd92`.
- Baseline handshake epoch was `1786853641`. It advanced through governance
  changes and suspend/resume to `1786854017`; the config digest stayed exact.
- Released owner DOM refetched accountable owner, managing team, lifecycle,
  effective permission summary, runtime revisions, credential revision, and
  WireGuard revision without exposing any secret.
- Append-only audit rows recorded group create/member add, both owner/team
  assignment transitions with old/new IDs, member profile updates, member
  removal, agent-source rule create/delete, and group deletion.

## Effective permission transitions

Accountable owner (live member session):

- profile/runtime/rotation GET: `200/200/200`;
- metadata manage: `200`;
- governance assignment: `403`;
- effective permissions: view/manage/revoke true; assign/grant/rotate false.

Managing-group member (same live member after owner restoration):

- profile/runtime/rotation GET: `200/200/200`;
- metadata manage: `200`;
- governance assignment: `403`;
- effective permissions: view/manage true; revoke/assign/grant/rotate false.

Unrelated member (same session after group-member removal):

- known profile, unknown profile, runtime status, rotation status, metadata
  mutation: `403/403/403/403/403`;
- known and unknown responses both normalized to `forbidden`.

The exact released-route suite at this content tip separately proves member
DOM absence and permission-shaped controls; the live member wire above proves
the backing authorization/no-oracle contract without recording its cookie.

## Access policy and organization switch

- Unrelated member agent-source create: `403`.
- Authorized owner create: `201`; list refetch count for the exact rule: `1`.
- Released Access route rendered
  `f06-rbac-live-20260816T0410Z -> aws-server` as an active standard rule, and
  rendered the disposable managing group.
- Switching the released route from `DEMO` to `demo2` synchronously produced a
  loading barrier with the old agent, group, rule, and Add-rule authority all
  absent before the next organization completed loading. Switching back
  restored the correct DEMO surface.
- Rule delete returned `204` and the live rule count became zero.

## Delegation withdrawal and lifecycle

- Removing the member from the managing group immediately changed its known
  and unknown profile access to uniform `403`.
- Deleting the managing group returned `204`, cleared
  `agent_profiles.managing_group_id`, preserved the canonical owner, and left
  the connected tunnel/config intact.
- A scoped accountable member suspended and resumed the agent. Both responses
  preserved the same owner and managing-group IDs; resume returned `active`
  and the real handshake advanced without config mutation.
- Final profile restoration: original owner, no managing group, empty original
  environment, active lifecycle.

## Migration and cleanup

Exact non-skipped PostgreSQL test:

`go test ./db -run '^TestAgentDelegatedRBACMigrationPostgres$' -count=1 -v`

Result: PASS. It proved empty `95 -> 94`, `94 -> 95` up-again, and non-empty
rollback refusal preserving both assignment and device row.

Cleanup:

- canonical agent revoke/remove: `204/204`; live roster count became zero;
- both disposable groups and the policy rule were absent from PostgreSQL;
- VM interface, config, private-key/runtime-credential scratch, CP response
  scratch, and local scratch were absent;
- `/dev/net/tun` remained present; unrelated users, gateways, policies, base
  packages, and AWS resources were not changed;
- final API/web/nginx health was green, restart counts zero, schema `95|false`.
