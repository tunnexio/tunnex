# AI user access and multiple roles

Status: accepted implementation scope, 2026-09-08. Continues `ai-improvement` after
the saved-credential testing slice. Local changes only; publication and merging
are outside this authorization.

The user requested Engineering-group model access without distributing provider
keys, a usable model endpoint, delegated `ai-admin` / `ai-view` administration,
and multiple simultaneous roles on a user. These are one end-to-end delivery.

## Locked decisions

1. Memberships carry a nonempty set of human roles: owner, admin, member,
   ai-admin, ai-view. Permissions are the union, scoped to the organization.
   Operator and agent remain machine-only and cannot enter a human role set.
   Existing memberships keep their role. A canonical primary role remains for
   compatibility with existing owner/admin relational checks; it is derived in
   the database, not chosen by a client.
2. The role update API accepts a complete `roles` array. Legacy `role` requests
   replace the previous primary role and preserve other assigned roles. Empty,
   duplicate, unknown, and machine role sets are rejected. User-role changes
   remain owner/admin operations; only owners can grant or modify ownership.
   Concurrent role changes serialize per organization for the last-owner guard.
   The roster offers explicit role checkboxes and Save, with all assigned roles
   visible. Removing one role preserves the others.
3. ai-admin can manage AI credentials, models, gateway configuration and group
   model grants. ai-view can read AI configuration and usage, but cannot mutate
   it or execute credential tests. Neither role grants VPN, organization, user,
   or role administration. Neither role alone grants model inference.
4. Model-use grants bind an existing user group to an exact configured model
   and its provider connection in the same organization. User groups are distinct
   from the existing device-based agent teams. Inference checks current active
   user, organization membership, group membership, grant, provider state and
   gateway opt-in on every request. Removing group membership withdraws access
   on the next request. No implicit owner/admin inference bypass.
5. Human inference reuses Tunnex login: browser session with CSRF protection, or
   the CLI's existing login credential. The public human endpoint is organization
   scoped; the UI supplies its exact URL and CLI example. Provider keys and engine
   virtual keys never reach the user. Existing agent-token endpoints remain
   separate. A new unauthenticated endpoint or independent long-lived AI bearer
   credential is rejected: neither is needed for the requested login-based use.
6. Reuse the existing bounded inference adapter and scoped engine keys. A group
   grant provisions a model-scoped private engine key; its encrypted value and
   readiness stay server-side. Failed provisioning cannot confer access. The
   existing mode validation, streaming bounds, and concurrency limits apply to
   human requests too. Browser and CLI calls identify the human rather than
   pretending a user is an agent device.
7. The AI screen provides model access management and a member-facing Use model
   path. The local reverse proxy forwards the required inference routes. Tests
   use synthetic users/groups/provider fixtures and preserve the user's saved
   Azure credentials and models.

## Acceptance and evidence

- Assign member + ai-admin, remove ai-admin, and observe member retained.
- Reject machine roles, empty role sets, unauthorized role changes, and removal
  of the final owner; verify session and CLI permissions refresh after changes.
- AI admin manages AI resources while VPN/user administration is denied; AI view
  reads those resources while all AI mutations and tests are denied.
- Four Engineering members can call their granted model through Tunnex login;
  an outsider cannot. Removing one member revokes their next request.
- The UI shows an actual endpoint and a usable CLI example, with no provider key
  exposure. Browser inference produces a real fixture response through the
  shared adapter. Unit results are substitutes, never claims of live proof.
- Run code generation checks, appropriate API tests/builds in both editions,
  relevant CLI tests, and web typecheck/tests/build. Record any unrun composite
  gates explicitly. Review findings are held for disposition under AGENTS.md.
