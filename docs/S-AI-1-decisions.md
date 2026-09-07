# AI-1: authenticated AI endpoint

Status: implementation contract; branch `ai-improvement`. Builds on AI-0's pinned
Bifrost qualification. No merge/release authorization is implied.

## Locked decisions

- **Community included**, explicitly ruled by user on 2026-09-07. AI has its own
  organization opt-in, absent/default OFF. It does not call the paid managed
  runtime opt-in gate or unlock unrelated runtime/MCP features.
- Reuse real managed-agent bootstrap enrollment and current runtime identity.
  Existing bootstrap supports Community. Candidate/grace/runtime-rotation
  credentials must not silently become AI credentials.
- `POST /agent/runtime/ai-credential` uses the current runtime bearer. It accepts
  no caller-selected tenant, device or audience. It returns an opaque `tnx_ai_`
  credential once, fixed audience `tunnex-ai`, expiry and inference path.
- Credentials contain 32 cryptographically random bytes. Persist SHA-256 only,
  fixed audience, org/device, runtime revision, creation/expiry/revocation. TTL
  five minutes; cap live credentials per device at four; issuance serializes on
  the canonical device row. No generic JWT/identity federation scheme.
- Every inference request checks current database state: org enabled/not deleted,
  device active/not deleted/not health-blocked, active/nondeleted owner and
  current org membership, current runtime credential revision, unexpired AI
  credential, and current fully applied AI policy. Pending/suspended/revoked
  identities fail. Database/CP loss denies new requests; no authorization cache.
- Preserve device-before-credential lock order. Recheck current identity after
  lock acquisition. Tenant-scoped foreign keys prevent cross-tenant credentials.
- `/ai/v1/chat/completions` and `/ai/anthropic/v1/messages` use the same qualified
  transport implementation. Document OpenAPI first; stream with a raw handler
  composed under canonical request/auth/error middleware. Avoid generated JSON
  response buffering for SSE.
- Transport allowlists identity/auth/provider headers and supported payload
  fields. Exact provider/model names only; no aliases, caller routing/fallback
  directives, alternate endpoints or upstream redirects. Default output bound
  1024 tokens, upper bound 4096; 256 KiB request body; complete connection lifetime
  30 seconds or credential expiry. Per-agent four active requests; deployment
  admission limit 64. Overflow returns 429, with no engine dispatch.
- New requests denied after authoritative revocation commits; a request already
  authorized/accepted may complete within its bounded lease. No promise of
  instantaneous upstream cancellation or reversal of incurred costs.
- Internal Bifrost keys stay server-side, sealed with the existing crypto
  implementation and a purpose/org/device/key binding envelope. Provider keys
  remain only in Bifrost environment/secret configuration. Never return upstream
  administrative responses or raw errors to users.
- New human permissions `ai_gateway:view` and `ai_gateway:manage`, owner/admin
  only. Management actions audited through the existing audit mechanism.

## Boundaries with AI-2/AI-3

Credential/transport code calls a policy resolver that must fail closed until a
desired policy is actually materialized and verified. Token possession does not
grant model access. AI-2 owns team assignment/model policy and desired/applied
reconciliation; its team composition decision is pending user disposition.

User approved **honest soft usage thresholds**. Exact-model verified pricing is
required whenever monetary limits are configured; unknown price refuses instead
of bypassing a limit. AI-3 owns measured accounting and customer-visible semantics.
Policy revisions must preserve native accounting identity/counters; generating a
new budget/key on every edit is not allowed to reset spend.

## Acceptance

Test both editions against isolated real PostgreSQL. Prove current/expired/wrong
audience/revoked/rotated credentials, pending/posture/owner-removal denial,
tenant isolation, concurrent mint cap, no plaintext persisted, Community enable
with paid runtime still locked, default-off and CP-loss refusal. Preserve existing
ordinary VPN and MCP regressions. Run generated-contract drift checks and required
final gates/CI before any merge. AI-2 resolver integration is required before the
customer endpoint is considered complete.

## Implementation and review addendum

Credential resolvers receive the caller-owned `pgx.Tx`. This preserves canonical
device-lock serialization without requiring a second pool connection; a real
PostgreSQL MaxConns=1 test verifies issuance and authorization. Refresh removes
expired, revoked and superseded-revision credentials for only that locked device.
Usable current credentials remain subject to the four-token cap. Idle rows remain
until the next successful refresh or canonical device/organization deletion.

Independent review found refresh accumulation and the inference error-envelope
mismatch; both were accepted as routine fixes and re-reviewed. Error responses
before streaming now use sanitized canonical JSON. A full spec auth walk also
found missing-bearer/unconfigured and settings-validation ordering defects; fixes
retain 401 before availability/body validation for unauthenticated callers.

Real database lock-wait tests demonstrate that issuance and authorization waiting
behind committed runtime revocation refuse. Key envelopes are tested against
cross-org/device/key/revision substitution and master-key mismatch.

The HTTP dependency seam is implemented and tested. **Production composition
remains unavailable until AI-2 supplies the verified policy resolver.** Config
fields, private-engine admin client and deployment overlay do not by themselves
make a production grant. Do not describe this checkpoint as a finished gateway.
