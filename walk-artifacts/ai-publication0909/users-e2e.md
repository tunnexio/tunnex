# Users browser regression — 2026-09-09

CI run34365992581 / job102518646286 failed waiting for the removed Users & Roles
navigation label. The test now follows Users & Groups and the role-set editor.
No product permission rules were changed.

Isolation verified before setup and API launch:

```text
COMPOSE_PROJECT_NAME=tunnexworkload0909
container=tunnexworkload0909-postgres-1
network=tunnexworkload0909_default
database=merge_users_e2e0909
schema=156 dirty=false
redis=tunnexworkload0909-merge-redis (persistence disabled)
api=127.0.0.1:18589
ui=127.0.0.1:5199
```

Ran `playwright test tests/users.spec.ts --workers=1` using Playwright1.48.2
against the integrated local API and UI with demo seed accounts. Final result:

```text
PASS a member sees the roster but no management controls
PASS an owner sees the invite form and per-member controls
PASS an unverified admin is offered no mutating controls despite the role
PASS the server (not just the UI) refuses a mutation from an unverified admin
PASS the sole owner's own role control is disabled with an explanation
PASS invite renders identically for an existing account vs a new email
PASS a role change in the UI appears in the audit log
7 passed (7.8s)
```

The role-set request and cleanup return the specified HTTP204. Unverified
requests to both legacy and role-set endpoints return HTTP403 with
`email_not_verified`. Cleanup replaces the complete role set with `member`.
E2E TypeScript compilation and `git diff --check` pass. The running user preview
and its saved credentials were not used or modified. This is local browser
regression evidence; fresh remote CI remains required for the pushed commit.
