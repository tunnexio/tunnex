# F09 permission and released-route evidence

The released live API returned uniform 403 for the unrelated member on both
group and template list routes; the normalized response contained neither the
disposable group nor template name. A fresh Chrome login as
`ai-agent-member@dev.tunnex.local` opened `/access`; the live DOM rendered the
member identity and only the notice `Access policies are managed by owners and
admins.` It contained no agent-group, template, version, preview, assignment or
apply facts/actions. Owner API mutations were server-refetched and the final
opt-in state was read back as false.

The exact-current released web suite passed in full before deployment: 79 files,
1,070 tests, TypeScript typecheck and production build. It includes owner
group/template/version/preview/apply callers, fresh server refetch, destructive
impact copy, unrelated-member DOM absence and organization-switch state
clearing.

The owner then logged in through the released route. Settings rendered the
default-off `Agent groups & policy templates` card; enabling refetched the
button to `Disable agent policy templates`. Access Policies subsequently
rendered the ordered `1. Agent group`, `2. Immutable template version`, agent
membership, destination/version selectors, `Preview impact`, and `Current
assignments` surfaces. No optimistic historical group/template state appeared.
After the proof, the supported owner API restored opt-in false and read it back.
