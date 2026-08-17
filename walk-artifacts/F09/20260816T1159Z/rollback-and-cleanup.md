# F09 rollback and cleanup evidence

Focused real-PostgreSQL proof passed:

```text
go test ./db -run '^TestAgentPolicyTemplatesMigrationPostgres$' -count=1
ok github.com/tunnexio/tunnex/apps/api/db
```

It proves empty 97->96 rollback, reapply to 97, unchanged legacy rule count and
compiled hash, plus populated rollback refusal preserving F09 state.

Supported lifecycle APIs revoked and soft-removed both disposable F09 agents;
the live-device count is zero. Consumed bootstrap JSON was deleted from CP
scratch. Final organization-scoped state:

```text
groups_live=0
members=0
templates_live=0
assignments_live=0
generated_bindings=0
f09_agents_live=0
opt_in=false
```

Two `f09-resource-*` destinations remain as inactive immutable-history
dependencies of archived template versions. They have no assignment, generated
binding or live grant. The verified rollback bundle remains intentionally for
recoverability. Shared API/web/nginx/node services stayed healthy.
