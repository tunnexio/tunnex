# Workload identity implementation review — 2026-09-09

Status: **Local CP rollout verified; production qualification incomplete.**

Subject: the uncommitted implementation on `story/S-AI-workload-identity`, based
on paper commit `4e0ffd66`. Existing work in the parent `ai-improvement` checkout
has not been replaced. The table retains the original findings and records their
current dispositions; test results alone are not a disposition.

## Ranked findings

| ID | Priority | Evidence and effect | Proposed correction | Disposition |
| --- | --- | --- | --- | --- |
| W1 | P1 | `workload_auth.go` maps infrastructure errors from live workload/org/instance lookups to terminal 401 responses. A database outage can therefore retire healthy clients. | Distinguish absent/invalid credentials from failed authorization storage; return retryable 503 for infrastructure errors. Add outage/recovery regressions. | Applied for the requested local CP rollout; regression verified |
| W2 | P1 | `workload.go`, `workloadTokens.get`, treats HTTP statuses other than 503 as terminal. Authentication admission can return 429; proxies can return 502/504. | Retry bounded transient failures, retain a still-valid token, and terminate only on confirmed credential refusal. | Applied for the requested local CP rollout; regression verified |
| W3 | P1 | `workloadSession.run` unconditionally calls `retire` after child exit, including an ordinary application failure. The persisted retirement marker blocks supervisor restart with the same state, including durable instances. | Separate explicit replica retirement from process exit. Preserve instance state for ordinary crashes/restarts and prove replacement versus restart behavior. | Applied for the requested local CP rollout; regression verified |
| W4 | P2 | `AIWorkloads.tsx` hides key actions after key-only revocation, while the API supports later combined descendant revocation. The instance table does not show its enrollment key. | Retain a clear action to revoke that key's instances, and show originating key context. | Applied for the requested local CP rollout; regression verified |
| W5 | P2 | Disabling a workload permanently revokes all enrollment keys, but warnings describe fresh tokens only. Connection detail loading ignores workload revision changes, leaving revoked keys displayed Active. | Explain replacement-key requirements and refresh dependent state after policy mutations. | Applied for the requested local CP rollout; regression verified |
| W6 | P2 | The model picker permits identical model names through multiple credentials and more than eight credentials. The API rejects both, giving a generic save error. | Reflect the backend's exact-model and credential-count constraints in selection and validation. | Applied for the requested local CP rollout; regression verified |

W1–W2: independent backend/CLI review. W3–W6: independent UI/lifecycle review,
confirmed against source by the primary agent. No additional permission bypass
was found in the access gate/navigation pass. UI review did not independently
reproduce these six findings against an installed API.

The user requested actual local CP rollout and an integrated redesign on
2026-09-09. W1–W6 were included as necessary corrections; evidence is in the local
CP box-walk. The independent rereview found and corrected a related model-picker
mode mismatch: changed provider modes now require explicit reselection. Original
pending MCP work remains untouched in the parent checkout and was not included
in this model-access rollout.

### Follow-up held for a separate retirement protocol slice

**W7, P2:** If remote retirement commits but its response is lost, the retired
instance cannot authenticate to confirm the result. A generic 401 must not be
reinterpreted as success. An authenticated idempotent retirement receipt requires
its own protocol decision and regression. Current operator guidance directs an
AI administrator to the authoritative Instances status and existing revoke
operation. Ordinary process restart does not retire instances and is unaffected.
This remains an explicit qualification limitation; the previous fake fixture
retry is not claimed as proof of post-commit retirement recovery.

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
- Story-end review of the complete remaining scope; no story-end acceptance or publication.

Current operator instructions are in [Workload model access](workload-model-access.md).
Local test evidence is recorded separately in the box-walk ledger.
