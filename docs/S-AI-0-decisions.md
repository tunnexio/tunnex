# AI-0: qualify the private AI execution engine

Status: in progress; not production-qualified. Branch: `ai-improvement`.
Base: `5199b62d15c5498bc8ede58703b9d5af5aa45c23`.
Strategy: [AI gateway epic](EPIC-ai-gateway.md). NAT is independent.

## Decision record

| Decision | Disposition |
| --- | --- |
| Engine ownership | Locked by epic: reuse private Bifrost, no fork, provider SDK engine, competing usage ledger, or upstream dashboard clone. |
| Qualification candidate | Bifrost `transports/v2.0.0`, source commit `e4a30d6041c0446603aea615bc5da340dac001b1`, resolved from the official annotated tag. Candidate only; source inspection and runtime tests must qualify it. Record artifact digest before runtime acceptance. |
| Live provider | OpenRouter, selected by user. Exact model, spend ceiling and secure credential location remain prerequisites for paid smoke requests. No secret values in Git, logs or evidence. |
| Scope of first slice | Local qualification harness and minimal adapter boundary, separate from production routes. Deterministic instrumented upstreams incur no provider spend. No CP schema or generated API changes in this slice. |
| Identity boundary | Tunnex owns authentication. Existing `agentruntime.Service.Authenticate` returns tenant/device identity and checks credential lifecycle; it does not itself establish AI-specific permission or audience. Harness credentials are synthetic fixtures, never a production identity scheme or proof of enrollment. |
| Adapter forwarding | Only explicitly supported inference paths; bounded bodies and lifetime; propagate cancellation and streaming. Construct upstream headers from an allowlist, inject only server-selected virtual key. Never forward caller cookies, credentials, identity, provider-selection or Bifrost control headers. No redirects or retries to alternative destinations. |
| Policy boundary | Exact model/tenant/agent to scoped virtual-key mapping in qualification fixtures. Separately test Bifrost-native denial with an instrumented provider; adapter-only denial does not qualify upstream enforcement. |
| Runtime isolation | Use a dedicated local runtime/data directory and loopback listeners. Never use existing CP/database containers or volumes. Docker is currently unavailable; do not restart a shared environment to hide that blocker. |
| Production identity and reconciliation | Deferred to AI-1/AI-2 decision papers after AI-0 qualifies the engine. Audience/TTL, team mapping, policy revision, opt-in and enforcement bounds must be explicit before production code. |
| Budget claims | Locked by epic: qualify reservation, actual charging, concurrent streams and restart persistence. Do not call asynchronous accounting a strict monetary cap. Material engine-fit failures require disposition before fallback or new implementation. |
| Revocation | New requests must fail within a measured bound. Termination of active streams is a separate unproven behavior, not implied by new-request denial. |

## Ordered acceptance

1. Pin source/artifact and inspect license, governance/admin API, secret/config and listener boundaries.
2. Exercise the adapter against deterministic HTTP/SSE servers: forged headers,
   cross-tenant/model denial, oversized requests, upstream redirects, cancellation
   and streaming. These tests are substitutes only for their local boundaries.
3. Exercise the pinned Bifrost process against an instrumented provider: native
   model denial has zero provider arrivals; authenticated allowed requests stream;
   bypass and admin paths refuse; usage/budget state survives restart.
4. With an approved OpenRouter model/spend and securely supplied credential, run
   a real enrolled-agent request through the identity adapter and the
   Anthropic-compatible streaming path. Redact all evidence.
5. Record measured accounting and policy limits, gaps and engine selection.
   AI-0 remains incomplete until these runtime and live proofs exist. AI-1 starts
   after the shared engine contract is frozen; independent lanes may then run.

## Initial verified state

- Planning documents already landed on main unchanged; local branch rebased onto
  main without reapplying their duplicate commit.
- Existing unrelated nested worktrees and saved stashes remain untouched.
- Go `go1.26.5 darwin/arm64` is available.
- Docker reports no daemon at its configured Colima socket.
- `OPENROUTER_API_KEY` is absent from the current process environment (value not read).
- No cloud, provider-spend, production configuration or release action performed.

## References

- [Pinned Bifrost source](https://github.com/maximhq/bifrost/tree/e4a30d6041c0446603aea615bc5da340dac001b1)
- [Virtual key documentation](https://docs.getbifrost.ai/features/governance/virtual-keys)
- [Governance configuration](https://docs.getbifrost.ai/deployment-guides/config-json/governance)

Documentation describes capabilities; it does not replace tests of the pinned release.
