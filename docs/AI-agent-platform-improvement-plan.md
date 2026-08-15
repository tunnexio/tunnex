# AI Agent Platform Improvement Plan

**Status:** Proposed implementation plan
**Baseline:** Tunnex `v0.1.1` clean-start repositories
**Related registration paper:** [`EPIC-15-zero-trust-for-ai-agents.md`](./EPIC-15-zero-trust-for-ai-agents.md)

This plan orders work from identity and lifecycle foundations through fleet operations and MCP-aware controls. The final story is intentionally limited to CSS and UX polish. An empty cell means that the story does not require a change in that layer.

**Status legend:** `⬜ Not started` · `🟨 In progress` · `✅ Done` · `⛔ Blocked`

| Feature / Story | Data changes | Backend changes | UI / Interface changes | Status |
|---|---|---|---|---|
| **F01 — Agent identity and lifecycle foundation** | Add an agent profile keyed to the existing device identity, carrying environment, runtime, labels, owner, and lifecycle state. Keep the device row as the canonical WireGuard identity. | Validate explicit lifecycle transitions: enrolled, active, suspended, and revoked. Keep human and agent identities distinct. | Add an agent details and metadata editor. | 🟨 In progress |
| **F02 — Multiple agents per gateway and organization quotas** | Remove the one-agent-per-gateway constraint. Add organization quota and allocation records while preserving unique agent identity and tunnel-address guarantees. | Enforce quota and tunnel-address allocation atomically under concurrent enrollment. | Show gateway capacity, used quota, and placement during enrollment. | ✅ Done |
| **F03 — Managed enrollment and bootstrap** | Store hashed, one-time enrollment tokens with expiry, consumption time, and issuing actor. Never persist a reusable plaintext bootstrap secret. | Add bootstrap APIs and supported Linux package/container installation paths. Bind enrollment to the intended organization and gateway. | Provide a guided enrollment wizard with copyable installation commands and progress state. | ✅ Done |
| **F04 — Runtime configuration synchronization** | Record desired and applied configuration revisions, runtime/client version, last-seen time, and last reported error. | Add authenticated configuration polling or streaming, automatic route refresh, reconnect behavior, and fail-closed handling for invalid revisions. | Show desired versus applied revision, connectivity state, and stale/error warnings. | ✅ Done |
| **F05 — Credential rotation and safe offboarding** | Record credential revision, expiry, revocation, and bounded rotation history. | Implement automatic WireGuard key rotation with bounded overlap, immediate revocation, and idempotent offboarding cleanup. | Add rotate, suspend, resume, and revoke actions with impact confirmation. | ✅ Done |
| **F06 — Agent ownership and delegated RBAC** | Store the accountable owner and optional managing team or delegated managers. | Add separate permissions for enrolling, viewing, managing, granting access to, and revoking agents. An agent must never receive policy-authoring authority implicitly. | Add owner/team assignment and a readable permission summary. | ⬜ Not started |
| **F07 — Truthful agent audit attribution** | Extend access events with source agent identity, matched policy and version, decision, deny reason, gateway, and configuration revision. Do not claim a human trigger until signed provenance exists. | Stamp attribution from the compiled enforcement artifact and preserve it through ingestion. Reject address-only inference as agent identity. | Add agent filters and an event-detail timeline showing identity, rule, route, decision, and reason. | ⬜ Not started |
| **F08 — Read-only “Test Access” diagnostics** |  | Add a non-mutating reachability evaluator for identity, policy, route, gateway, DNS, protocol, port, expiry, and applied revision. Permit an optional bounded safe probe. | Let the operator select an agent and destination and receive a step-by-step pass/fail explanation with the exact blocker. | ⬜ Not started |
| **F09 — Agent groups and reusable policy templates** | Add agent groups, group membership, versioned templates, and template-assignment records. | Preview resolved policy impact before applying a template. Reuse the existing policy compiler instead of creating a parallel authorization model. | Add group management, template creation, preview, and bulk assignment flows. | ⬜ Not started |
| **F10 — Just-in-time access requests and approvals** | Add request, approval, rejection, expiry, cancellation, and revocation records with actor and timestamp provenance. | Implement an idempotent request state machine, maximum TTL enforcement, automatic expiry, and emergency revoke. | Add an agent access-request form and administrator approval inbox with explicit destination and duration. | ⬜ Not started |
| **F11 — Alerts, webhooks, and SIEM export** | Add organization alert subscriptions and a retryable delivery outbox with attempt history. | Produce signed, retryable events for offline agents, denial spikes, expiring access, rotation failures, and configuration drift. Support audit export without weakening tenant isolation. | Add alert configuration, webhook testing, delivery status, and failure history. | ⬜ Not started |
| **F12 — MCP server and tool inventory in shadow mode** | Store MCP servers, tools, resources, schema hashes, versions, and first/last-seen timestamps. | Introduce an MCP-aware observation path that discovers inventory without enforcing tool decisions. Measure compatibility and latency before enabling L7 blocking. | Add MCP inventory, server health, and newly discovered or changed-tool views. | ⬜ Not started |
| **F13 — MCP OAuth and protected-resource trust** | Store issuer metadata, protected-resource URI, scopes, client metadata, and secret references. Never store access tokens as ordinary configuration data. | Implement OAuth authorization discovery, resource/audience validation, secure token handling, and explicit rejection of token passthrough. | Add an MCP connection wizard showing issuer, protected resource, requested scopes, consent, and connection status. | ⬜ Not started |
| **F14 — MCP per-tool policy enforcement** | Add versioned allow/deny rules keyed to stable MCP server and tool identities. Newly discovered tools remain denied until explicitly allowed. | Validate authoritative MCP request content, reject header/body mismatches, and enforce tool policy before forwarding. Keep L3/L4 enforcement as the fail-closed network boundary. | Add server-to-tool permission selection with a clear default-deny state. | ⬜ Not started |
| **F15 — Signed workflow and run provenance** | Store workflow/run ID, trigger, initiator, signer, claims, signature, and verification outcome. | Define an agent SDK or signed request envelope and verify provenance before attributing a request to a workflow or human trigger. | Show a verified Agent → Run → Tool → Resource chain, and label unsigned context as unverified. | ⬜ Not started |
| **F16 — Argument controls, rate limits, and step-up approval** | Store JSON-schema constraints, usage limits, destructive-action classifications, and step-up decisions. | Validate arguments against server-owned constraints, enforce per-agent/tool limits, and pause classified operations for approval without exposing secrets. | Add an argument-constraint editor, rate-limit controls, and live approval prompts. | ⬜ Not started |
| **F17 — Final CSS and UX polish** |  |  | Complete responsive layouts, accessibility, terminology, loading/empty/error states, spacing, and visual consistency after behavior is stable. | ⬜ Not started |

## Release sequence

1. **Reliable Agent Fleet — F01 through F08**
   Multiple managed agents can enroll, remain synchronized, rotate safely, produce truthful audit evidence, and be diagnosed without mutating policy.

2. **Enterprise Operations — F09 through F11**
   Teams can reuse policy, request temporary access, and integrate operational events with their monitoring and compliance systems.

3. **MCP-aware Security — F12 through F16**
   MCP discovery ships in observation mode before enforcement. OAuth trust precedes per-tool policy, and signed provenance precedes any initiating-trigger claim.

4. **Final polish — F17**
   CSS and UX cleanup begins only after the behavior and interfaces are stable.

## Delivery rules

- Each story must produce one narrow, observable customer outcome and stop when that acceptance path passes.
- Schema changes must have forward and rollback behavior, organization scoping, and preservation proof.
- Enforcement changes must be fail-closed and must include a deliberate red test proving the guard is exercised in the real stack.
- UI must not fabricate unavailable identity, trigger, policy, health, or audit data.
- MCP shadow mode must demonstrate compatibility and bounded overhead before per-tool enforcement is enabled.
- A story is complete only when its production-shaped API, enforcement behavior, rendered interface where applicable, and focused tests agree.

## Explicit non-goals for this plan

- Hosting or orchestrating customer models.
- Detecting prompt injection from network traffic.
- Treating client-reported model/runtime metadata as attestation.
- Replacing the existing L3/L4 policy engine with the MCP L7 layer.
- Claiming human or workflow attribution for unsigned requests.
