# Workload identity implementation review — 2026-09-09

Status: **INCOMPLETE — findings held for disposition. Not production-ready.**

Subject: the uncommitted implementation on `story/S-AI-workload-identity`, based
on paper commit `4e0ffd66`. Existing work in the parent `ai-improvement` checkout
has not been replaced. Passing tests below do not resolve these findings.

## Ranked findings

| ID | Priority | Evidence and effect | Proposed correction | Disposition |
| --- | --- | --- | --- | --- |
| W1 | P1 | `workload_auth.go` maps infrastructure errors from live workload/org/instance lookups to terminal 401 responses. A database outage can therefore retire healthy clients. | Distinguish absent/invalid credentials from failed authorization storage; return retryable 503 for infrastructure errors. Add outage/recovery regressions. | Held |
| W2 | P1 | `workload.go`, `workloadTokens.get`, treats HTTP statuses other than 503 as terminal. Authentication admission can return 429; proxies can return 502/504. | Retry bounded transient failures, retain a still-valid token, and terminate only on confirmed credential refusal. | Held |
| W3 | P1 | `workloadSession.run` unconditionally calls `retire` after child exit, including an ordinary application failure. The persisted retirement marker blocks supervisor restart with the same state, including durable instances. | Separate explicit replica retirement from process exit. Preserve instance state for ordinary crashes/restarts and prove replacement versus restart behavior. | Held |
| W4 | P2 | `AIWorkloads.tsx` hides key actions after key-only revocation, while the API supports later combined descendant revocation. The instance table does not show its enrollment key. | Retain a clear action to revoke that key's instances, and show originating key context. | Held |
| W5 | P2 | Disabling a workload permanently revokes all enrollment keys, but warnings describe fresh tokens only. Connection detail loading ignores workload revision changes, leaving revoked keys displayed Active. | Explain replacement-key requirements and refresh dependent state after policy mutations. | Held |
| W6 | P2 | The model picker permits identical model names through multiple credentials and more than eight credentials. The API rejects both, giving a generic save error. | Reflect the backend's exact-model and credential-count constraints in selection and validation. | Held |

W1–W2: independent backend/CLI review. W3–W6: independent UI/lifecycle review,
confirmed against source by the primary agent. No additional permission bypass
was found in the access gate/navigation pass. UI review did not independently
reproduce these six findings against an installed API.

The consolidated disposition request covers W1–W6 and the previously held MCP
B3–B6/B9 corrections needed before shared OAuth reuse. No held finding has been
folded. The authoritative older list remains
[MCP authenticated discovery review](S-MCP-authenticated-discovery-review.md).

## Receipt retry clarification

Recovering an existing public enrollment receipt with the original signing key,
request ID and still-active generation-one instance does not create a new join or
restore authority. Key-only revocation intentionally preserves registered
instances; combined/instance/workload revocation still refuses the relevant
authority. Such a receipt contains no bearer token and does not consume another
enrollment use. The review did not classify this retry as an authorization defect.

## Remaining implementation and qualification

- Central authenticated MCP execution and resource-bound authorization.
- Explicit legacy-to-workload mapping preview and access-parity proof.
- Shared admission limits and complete public authentication metadata.
- Multiple API replica, restart, expiry, outage and failover qualification.
- Windows runtime permission handling and a native Windows execution walk.
- Re-review after dispositioned fixes; no story-end acceptance or publication.

Current operator instructions are in [Workload model access](workload-model-access.md).
Local test evidence is recorded separately in the box-walk ledger.
