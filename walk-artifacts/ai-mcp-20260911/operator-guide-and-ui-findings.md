# AI features: walk result and simpler user journey

## Live coverage

| Area | Verified |
| --- | --- |
| AI Gateway | Configured GPT-5 chat, browser invocation, streamed response, allowed/denied model access, short-lived runtime credentials, usage attribution, missing-price threshold refusal |
| Workloads | Single-use/reusable enrollment, replica limits, rotation, key-only revocation, key plus instance sweep, individual revoke, disable/re-enable, old-token refusal, replacement enrollment |
| MCP | Discovered inventory and source, default deny, tool allow/deny, argument constraints, rate limit, one-use step-up, real Cloudflare OAuth inventory and read tool, provider revoke refusal |
| AI Agents | Enrollment prerequisites, connected runtime, runtime/WireGuard rotation, model grant withdrawal, signed provenance, replay/bad-signature labeling |
| Policy templates | Isolated enforced destination/port allow, adjacent port deny, withdrawal removes access |
| JIT | Pending, approve, reject, cancel, revoke, duplicate-create protection, natural five-minute expiry, audit history and managed rule removal |

Only GPT-5 chat is configured. Embeddings, images, audio/transcription, rerank and video are **unconfigured**, as requested. Natural OAuth refresh, interrupted rotation recovery and JIT-specific enforced packet expiry remain separate qualification gaps. The template test used enforcement; the Demo JIT lifecycle test deliberately kept enforcement off. These are different proofs.

## How users should use the features

1. **AI Gateway:** add provider credentials, choose a deployment, test it, and grant a user group access. The user connects Tunnex VPN and copies the model name and displayed SDK Base URL from My models. The single-membership URL is `https://internal.tunnex.app/ai/v1`; copy the displayed organization-specific URL when membership is ambiguous. Provider keys stay with the gateway.
2. **Workloads:** use a workload identity for unattended applications. Restrict its models, issue an enrollment key, enroll instances, and use the local SDK proxy. Workload credentials are separate from a human's VPN identity.
3. **AI Agents:** enroll the runtime, confirm Connected/Ready, then assign only the model, MCP and network permissions required by that agent. Activity explains verified workflow context and access decisions.
4. **MCP:** add a server profile, attach it to the agent, complete OAuth when required, wait for observed tools, and explicitly allow selected tools. A profile alone does not grant tool access. Arguments, rate limits and step-up approval add separate constraints.
5. **Policy templates:** reusable network access for an agent group, such as a build agent reaching one private database on one port. Applying the template creates managed network rules; withdrawing it removes them. It does not grant AI models or MCP tools. Actual network restriction requires enforcement in the target organization.
6. **Just-in-time access:** request a destination for a short duration, approve when needed, and let it expire or revoke it early. Pending requests add no rule. Enable the organization capability explicitly before use.

## UI findings, ranked for the next design pass

| Priority | Finding | Recommended user experience |
| --- | --- | --- |
| P2 | JIT fetches50requests and discards the next cursor | State filter and Load more so old actionable requests stay reachable |
| P2 | MCP OAuth copy implies no tokens ever reach an agent | Explain that refresh/client secrets stay in CP; transient access leases are kept in runtime memory |
| P3 | JIT expiry and sibling Rules were misleading | Fixed and deployed: exact deadline, automatic rule readback after approve/revoke |
| P3 | Admin cannot see Cancel for their own pending request although API permits it | Keep requester cancellation available; use a normal rejection dialog with a required reason |
| P3 | Agent JIT card has no next action | Link directly to scoped request/approval controls |
| P3 | Browser model output starts with raw JSON | Show answer and usage first; put raw response under Details |
| P3 | Spend-by-model says no usage when only pricing is unavailable | State cost unavailable, preserve actual request/token counts |
| P3 | Setup steps spread across pages | Contextual next-step links: connect provider → grant access → copy SDK example; attach MCP → discover → allow tools |
| P3 | Non-chat use panels lack operation-specific examples | Show examples for the selected operation and label unconfigured modes clearly |

The optional numeric budget clear attempt did not change the field using the browser automation fill operation. This remains inconclusive between input tooling and product behavior; no unsupported backend bug claim.

## Cleanup and delivery

Temporary OAuth grant, isolated network org and two network lab EC2 instances were removed under the user's exact cleanup approval. Test workload is disabled with all keys/instances revoked. Demo JIT returned off with no pending/approved requests. Original fixture agent is retained for future verification. Production VPN enforcement was not changed.

Two new JIT display fixes are deployed as web85c56bd5. Prior MCP/OAuth/runtime fixes and detailed artifact hashes are in the adjacent ledgers. Full web suite1517tests, typecheck and build passed. OAuth runtime fix was proved on the disposable agent before cleanup; it is committed but not installed on the retained original fixture or published as a new release.
