# AI/MCP walk fixes

User approved fixing observed bugs and continuing the live walk on 2026-09-11.

- Locked: correct UI permission identifiers against generated RBAC; preserve server authorization.
- Locked: MCP profiles show observed tools, their source agent and freshness; never imply profile creation alone proves discovery or enforcement. Reuse per-agent inventory APIs.
- Locked: expose useful missing-resource guidance in policy templates; support API-authorized destination selection without inventing permissions.
- Locked: explain runtime capability/opt-in prerequisites before bootstrap. Preserve paid entitlement and default-off opt-in.
- Locked: investigate opt-in recovery and OpenAI completion-token compatibility from evidence before changing behavior. Do not retry revoked credentials or weaken authentication.
- Locked: use configured models for agent policy selection rather than requiring model-ID discovery elsewhere.
- Locked: preserve existing deployed VPN identity/URL changes as local dependencies. New branch starts at current origin/main d378e332, then includes approved deployed story/ai-vpn-identity history.
- Deferred: third-party OAuth proof requires an actual configured provider; synthetic echo proof is labelled as such.

Verification: targeted regression tests, relevant web/API/CLI gates, then isolated AWS agent live allow/deny, model inference and template walk. No unrelated root working-tree edits. No merge or release requested.

Continuation: the live walk exposed an argument-constraints placeholder that omits the OpenAPI-required properties field. Locked: show a contract-valid example, reject missing required/properties locally with actionable guidance, and retain server-side validation. Do not broaden the supported constraint language. Network enforcement remains Off in Demo; its zero-rule confirmation warns all traffic would be denied. Separate network-walk scope is pending user disposition.

Locked continuation: Add Agent must read the current organization's runtime opt-in when opening; a stale shared UI snapshot cannot decide availability. Use the existing organization read endpoint and preserve server bootstrap authorization. Unknown/read-error is a retryable unavailable state, never Off or permission to issue. Visual fixtures may use their explicit state. No new auth or persisted-state model.

## OAuth inventory authentication (live walk)

Locked: reuse the existing endpoint-bound runtime OAuth lease for read-only MCP inventory discovery. The connected provider currently returns 401 because discovery never supplies this lease although tool forwarding does. Keep tokens in memory, never in inventory/report/errors; refuse redirects for authenticated discovery. Lease failure must not fall back to anonymous discovery. Public discovery remains supported. No new grant or authentication path is introduced.

Review disposition: fix P1 cache isolation in the same slice. Store and compare the exact endpoint with every cached lease; the former cache could reuse A's bearer after switching to B. Regression proves A-to-B fetches a new lease and B-to-B reuses only B's lease. Final bounded review found no further actionable regression.

## JIT live-walk display corrections

Locked under the user's approved bug-fix walk: refresh the sibling policy table after successful JIT approval/revocation using its existing revision trigger. Display the exact localized expiry timestamp, never the past-age formatter for a future deadline. Preserve the shared last-seen formatter and all server authorization. These are presentation corrections, with no new state model or enforcement change.

Additional UI findings remain ranked for the follow-up: pagination/state filters, requester cancellation hidden for admins, native rejection prompt, and navigation from the agent detail card. This slice does not change those workflows.

## Approved UI follow-up

User explicitly requested implementation of the ranked UI improvements after the walk. Locked: use existing JIT state/device filters and keyset cursor with bounded Load more, discard stale responses on filter/org changes; allow original requesters to cancel including admins; replace native rejection prompt with an accessible required-reason modal. Link agent detail to the scoped JIT workspace. Keep permissions and enforcement server-owned.

Locked: show chat answer and available usage before expandable raw response; correct missing-cost and OAuth credential copy; add contextual navigation between existing setup screens and operation-specific examples. Non-chat examples use authenticated requests and never imply dummy-key VPN support for unsupported operations. Do not fabricate deployment availability or pricing. Preserve existing branding/layout, no new backend state or auth path. Validate regressions, full web gates and rendered browser states before completion.
