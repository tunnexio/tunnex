# Cross-Screen Status, Action, and State Matrix

## Status taxonomy

| Kind | Source and freshness | Required UI meaning / next action |
|---|---|---|
| Healthy / active | server status plus `last_seen_at` or domain health derivation | State why it is healthy and show “last reported/handshake”; link to the owning detail workspace. |
| Needs attention / degraded | canonical view helpers (`healthview`, `gatewaysview`, `agentview`, `postureview`) | Show the reason beside the label; do not collapse different failure sources into one badge. |
| Pending | server lifecycle/status; no assumed completion | State what is waiting on whom, deadline/expiry if known, and a refresh/recovery action. |
| Offline | last handshake/report exceeds domain window | Show the observed timestamp and “not proof of host failure” where protocol semantics require it. |
| Unknown / stale | report missing, failed, or too old | Never render as healthy or zero; say which dependency did not report and provide retry/context. |
| Revoked / deleted / archived | terminal server state | Suppress liveness claims; show cause, timestamp, recovery if allowed, and audit link. |
| Policy blocked | policy decision/evaluation source | Identify subject, destination, policy version/reason, and safe contextual action. |

## Common page states

| State | Required rendering |
|---|---|
| Loading | skeleton/`Loading`, preserving header and avoiding an “empty” claim. |
| Empty | explain the first safe action and its prerequisite; never show a dead CTA to an unauthorized user. |
| Partial | retain successful slices, label unavailable data, and give scoped retry—not a whole-page false error. |
| API error | durable in-context error with retry, request ID where returned, and no stale-success implication. |
| Permission denied | explain required role/capability and owner; do not show edition marketing. |
| Edition unavailable | explain plan boundary only after permission is known; show no red failure. |
| Offline | prevent security mutations; label cached/stale data and offer reload after reconnection. |

## Action hierarchy

- **Primary:** exactly one next operator job (Add gateway, Add agent, Add device, Add rule).
- **Secondary:** frequent safe actions (filter, export, refresh) adjacent to the primary action.
- **Overflow:** uncommon mutation/actions scoped to a selected row/detail header.
- **Destructive:** separated visually; confirmation states target, precise impact, no-op/refusal conditions, irreversible/recovery statement, and post-action audit link.

## Audit evidence rule

Every action that changes access, topology, credential validity, or configuration must expose the relevant Audit Log filter after success. The UI must not infer success from a `204`; it must refresh server truth and state the resulting lifecycle/impact.
