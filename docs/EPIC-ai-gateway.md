# Epic: identity-based AI gateway without shared provider keys

Status: development plan, not implemented or acceptance-tested by this document.
Planned against main `231f63f493641caacb2ff3d2f409f7ac06825b24` on 2026-09-06.
Story namespace: AI. Independent of NAT traversal and relay deployment.

## Customer outcome

A customer enrolls an agent with Tunnex and gives it an AI endpoint, without
giving the agent an upstream provider API key. The customer can decide which
models a team or agent may use, apply usage controls, attribute consumption and
revoke access centrally. Existing private-service access and MCP authorization
remain useful alongside this new LLM-provider access plane.

“Keyless provider access” means provider keys stay on the customer-controlled
gateway. It does not mean requests are unauthenticated: the agent presents a
short-lived, scoped Tunnex credential or an appropriate workload identity.

## Reuse decision: Bifrost first, not another LLM proxy

Use Bifrost as a separate, private service with a narrow Tunnex identity adapter.
Reuse its provider integrations, streaming, virtual keys, model restrictions,
usage accounting and available budget/rate-limit enforcement. Do not fork it,
rebuild vendor SDK adapters, or reproduce its administration dashboard for MVP.

Upstream describes OSS governance support, while enterprise RBAC/SSO are separate.
Its repository root license is Apache-2.0. This is a planning input, not proof
that every required capability exists in every release or deployment topology.
AI-0 must verify the selected release, APIs, plugins and license boundaries.

**Fallback:** evaluate LiteLLM only if Bifrost fails a concrete required fit test.
LiteLLM is an established alternative with core MIT licensing and separate
enterprise terms. Spend at most one additional engineer-day comparing the failed
capability and integration effort; do not turn this into an open-ended gateway
benchmark or adopt two engines for MVP.

| Concern | Single owner / implementation boundary |
| --- | --- |
| Agent enrollment, tenant/team identity and authorization intent | Existing Tunnex identity and policy model |
| Provider credentials | Bifrost's supported secret/config mechanism; do not duplicate plaintext secrets in CP |
| Tenant/agent policy desired state | Tunnex CP, with versioned idempotent reconciliation |
| LLM execution and materialized restrictions | Private Bifrost service; scoped internal virtual keys |
| Usage/budget accounting | Bifrost's qualified native mechanism; no second competing spend ledger |
| Identity adapter | Authenticate, authorize and map identity to a scoped internal credential; stream requests/responses |
| Customer experience | Small setup/status/policy surface in Tunnex; advanced upstream features may retain upstream UI |

The adapter must remove caller-supplied identity and internal-auth headers before
creating trusted upstream context. A WireGuard source IP alone is not agent
identity. Bifrost's data and admin listeners must not offer an unauthenticated
bypass around Tunnex enforcement. A scoped internal key must never become a
shared master key distributed to agents.

## Bounded development stories

Points estimate relative complexity, not elapsed days. Re-estimate after AI-0.
Each story has one independently reviewable customer or security outcome.

| Story | Pts | Outcome and acceptance | Depends on / repositories |
| --- | ---: | --- | --- |
| AI-0: qualify one upstream engine | 3 | Two engineer-day timebox: pin Bifrost release/digest; verify OSS policy/admin APIs, secret handling, streaming, usage and budget persistence. Run an enrolled-agent request through a minimal identity adapter to a real provider, plus an Anthropic-path streaming compatibility check. Prove denied models never reach an instrumented upstream. Record fit gaps and select Bifrost or the bounded fallback. | None; tunnex |
| AI-1: authenticated AI endpoint | 3 | Agent uses short-lived audience-bound identity; no provider key on client. Reject forged identity headers, wrong tenant/audience, expired credentials and revoked access. Authenticated streaming works with bounded request sizes/timeouts and cancellation. | AI-0; tunnex; tunnex-client only if a credential-helper change is required |
| AI-2: reconcile team/model policy | 3 | CP maps team/agent restrictions to scoped Bifrost configuration idempotently. Model aliases, routing and provider fallback cannot broaden permission. Partial reconciliation is visible and does not mark an unenforced policy active. | AI-1 contract; tunnex |
| AI-3: trustworthy usage controls | 5 | Attribute requests, tokens and available costs to tenant/team/agent. Test streaming, retries, cancellation, concurrent requests and restart persistence. Expose only the budget semantics actually proven; no duplicate accounting on retries. | AI-2; tunnex |
| AI-4: supported installation and onboarding | 3 | Customer enables the optional gateway, stores provider credentials server-side, grants a model policy and runs a sample agent. Reuse current installer/Compose and Helm lifecycle conventions; check upgrade persistence, private listeners and disable/rollback behavior. | AI-0 deployment contract; tunnex + tunnex-web, integrated after AI-3 |
| AI-5: customer walkthrough and beta | 3 | Demonstrate team isolation, model denial, attributed usage, budget behavior and revocation on a real install. Publish examples and limits with redacted screenshots. Verify existing MCP and ordinary VPN paths are unchanged. | AI-1–4; tunnex + tunnex-web |

Total initial estimate: 20 points. A failed fit test is a decision checkpoint;
it does not authorize silently implementing a new gateway or financial ledger.

## Fast execution order

1. Complete AI-0 before UI work. Write down the exact authentication, policy-sync,
   accounting and upstream-version contract that passed.
2. Then run identity/endpoint work, policy/accounting work, and deployment/docs
   work in parallel against shared fixtures. One integration owner maintains
   the contract and acceptance checklist.
3. Prefer server-side integration: do not make every desktop client release a
   dependency unless the existing workload credential path genuinely requires it.
4. Bundle one qualified engine by default. Preserve a configuration seam for an
   existing customer Bifrost endpoint, but do not build a generic multi-engine
   framework or support unqualified upstream versions in the first release.
5. Small opt-in PRs, focused regression tests per change, then applicable full
   exact-final gates and independent review before release. Keep NAT off the
   critical path. Do not rebuild an entire cloud environment for each policy fix.

## Budget semantics: an explicit release decision

Do not label an asynchronous usage threshold a strict monetary cap. AI-0/AI-3
must establish when quota is reserved, when actual usage is charged, what a
streaming request can consume, and how concurrent requests affect overshoot.
Test the selected persistence store through restart, not just an in-memory demo.

- If upstream provides the required reservation/enforcement semantics, reuse
  them and document the measured boundary.
- If it provides soft thresholds, label them honestly. Restrict concurrency and
  output limits where supported, measure residual overshoot and request product
  disposition before claiming strict spending limits.
- Unknown model prices must be explicitly configured or visibly uncosted; they
  cannot silently bypass a policy that requires cost enforcement.
- Provider billing adjustments and missing usage reports are not magically
  exact invoices. Distinguish observed tokens/cost estimates from provider bills.
- Start with a qualified single-instance deployment. Advertise HA only after
  shared-budget and reconciliation behavior is tested across multiple instances.

## Compact acceptance matrix

| Scenario | Required evidence |
| --- | --- |
| Happy path | Actual provider response and streaming; no upstream secret returned or placed on agent |
| Authorization | Model denial, tenant separation, forged headers and revoked identity rejected before upstream execution |
| Policy changes | Tightening takes effect within a documented bound; stale/failed sync is visible and fail-closed for affected new requests |
| Quotas/accounting | Requests, retries, cancellations, missing usage, concurrent streams and restart behave according to the published semantics |
| Failure | Engine/CP/provider outage has bounded behavior; no direct-provider/key bypass; retries stay inside authorized targets |
| Operations | Secrets rotate; private admin/data listener configuration holds; install, upgrade and rollback preserve the documented state |
| Existing product | Ordinary private-service access and existing MCP tool policy still pass their relevant regressions |

Most negative cases use deterministic instrumented upstreams with zero provider
spend. Run only a small authorized real-provider smoke/streaming walkthrough.
Store versioned redacted evidence, never prompts containing customer secrets,
provider keys, identity tokens or full sensitive response bodies. Prompt/response
logging is off by default; operational logs contain minimal attribution metadata
with explicit retention. Screenshot instructions must include secret redaction.

If a fix changes accounting, repeat accounting and adjacent authorization tests,
not every unrelated installer/cloud scenario. The final candidate still needs
the repository-required exact-SHA gates; this planning-only commit's CI skip is
not a product-code testing exemption.

## Non-goals and honest boundaries

- Not a universal agent sandbox, prompt-injection defense, or prevention of calls
  made with independently obtained provider credentials outside this gateway.
- Not a replacement for Tunnex MCP tool policy, tool approvals or private-network
  authorization; do not switch on a competing MCP plane merely because upstream
  offers one.
- No custom provider SDK engine, generalized billing system, provider marketplace,
  or automatic cloud identity federation for every vendor in MVP.
- Revocation blocks new requests within a documented bound. State separately
  whether already-running streams are terminated; do not imply instantaneous
  cancellation of upstream work that has already incurred cost.
- Provider outage handling and multi-provider fallback must not widen allowed
  models, data destinations or customer retention requirements.

## References

- [Bifrost repository](https://github.com/maximhq/bifrost)
- [Bifrost root license](https://github.com/maximhq/bifrost/blob/main/LICENSE)
- [OSS governance overview](https://www.getmaxim.ai/bifrost/resources/governance)
- [Bifrost budgets and limits](https://docs.getbifrost.ai/features/governance/budget-and-limits)
- [Bifrost governance configuration](https://docs.getbifrost.ai/deployment-guides/config-json/governance)
- [LiteLLM documentation](https://docs.litellm.ai/) and
  [license boundary](https://github.com/BerriAI/litellm/blob/main/LICENSE)
- Existing baseline: [zero trust for AI agents](EPIC-15-zero-trust-for-ai-agents.md),
  [MCP decisions](F14-decisions.md), [harness-neutral runtime decisions](F19-decisions.md).
- Companion: [NAT traversal and relay](EPIC-nat-traversal-relay.md).

External capabilities reviewed on 2026-09-06; AI-0 must qualify the exact shipped
upstream release. A plan or successful mock test is not evidence of live support.
