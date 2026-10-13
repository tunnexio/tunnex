# Actual owned cross-organization qualification (source only)

The existing synthetic member/admin/ai-view users are not CP-admins. `tenancy.Service.checkMayCreateOrg` allows organization creation only for first-ever bootstrap or an existing CP-admin. `CreateOrganization` also checks licensed organization capacity. Therefore the proposed member-created OrgB cannot succeed on this deployment through supported normal APIs. No credential, privilege, licence or database change is authorized by this plan.

## Supported creation and cleanup seams

- `POST /api/v1/organizations` with a fresh reviewed `{name,slug}` returns201 and assigns the creator owner. It has no caller-selected organization UUID or idempotency key. An unknown response must be reconciled using the creator's normal `GET /organizations` and exact fresh slug/name; never repeat the POST.
- `GET /organizations/{id}` and `/members` verify exact ownership.
- `DELETE /organizations/{id}` is owner-only, returns204 and has no CAS parameter. It refuses409 while sites, nodes, devices, Kubernetes clusters or machine credentials remain. Empty OrgB needs no SiteB for basic actual organization isolation.

## Minimum real OrgB test, contingent on separately approved prerequisites

1. Use an already authorized existing CP-admin normal identity and verify capacity without changing the licence. Persist exclusive creation intent with unique name/slug and immutable original-organization/member/provider/resource/policy/site/node baselines.
2. Create one empty OrgB once. Bind only the returned canonical UUID and exact name/slug, creator owner membership and empty resources. Do not infer ownership from a name match after an uncertain outcome.
3. Log in normally as synthetic adminA, prove OrgB absent from its organizations and its OrgA role unchanged. GET real OrgB, its members/sites/providers, and real OrgA provider ID under OrgB must return404. Malformed OrgB configuration-check/create/intent/rotation/delete requests use only an impossible provider and invalid body, and must return404 before validation. Never direct a mutation to a live OrgA provider.
4. Preserve original hashes. Creator normally deletes only exact empty OrgB after a separate reviewed cleanup release and fresh owner/name/slug/empty-state proof. Persist intent before one DELETE; unknown deletion response is GET-only reconciliation.

Creating OrgB through the existing CP-admin avoids adding invitations or synthetic accounts, but requires that identity and capacity to be explicitly approved. If these prerequisites are unavailable, use a separately isolated actual API/DB integration fixture and label it local HTTP tenancy proof, not live AWS cross-org acceptance. No runtime execution is part of this file.
