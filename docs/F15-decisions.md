# F15 — Signed workflow and run provenance decisions

Status: **In progress**. This paper is commit one. It begins from main after
F13 OAuth trust and F14 MCP tool-policy enforcement. F15 does not grant tool
access; it makes a workflow or human trigger claim truthful when evidence is
present.

## Acceptance question

Can a managed agent submit a bounded, signed workflow-run assertion and let an
operator see a verified **Agent → Run → Tool → Resource** chain, while every
missing, expired, replayed, malformed, or unverifiable assertion remains
explicitly unverified rather than being inferred from ownership or a token?

## Evidence and standards considered

- MCP 2025-11-25 defines OAuth authorization for HTTP MCP transports, not
  workflow/run provenance. F13 continues to own resource-bound OAuth tokens.
- RFC 9421 signs HTTP messages, but its HTTP-header canonicalization is not
  suitable as F15's portable SDK payload contract: the agent may report after
  the tool invocation and intermediaries can alter request representation.
- RFC 9449 DPoP sender-constrains OAuth tokens. It does not bind a workflow,
  run, tool, or resource claim. It is therefore out of scope for F15.

## Decisions — locked

### D1 — A separate signed assertion, not an inferred audit label

The agent submits one JSON assertion containing only: assertion ID, workflow
ID, run ID, trigger kind, initiating subject reference, tool name, resource
identity, issued-at, expiry, and the signing key ID. The signature covers a
server-defined canonical serialization of those claims. F15 never derives a
human or workflow from device ownership, OAuth identity, network address, or
current policy.

### D2 — Ed25519 keys registered to the managed-agent identity

Use Ed25519 public keys held by the control plane and key IDs bound to the
agent device. The SDK/agent owns private-key storage; the API stores only the
public key, lifecycle, and revocation state. Ed25519 keeps a small portable
envelope and uses Go's standard cryptography package. No new identity provider,
key-management service, JWT issuer, or generic signing framework is added.

### D3 — Short-lived, one-use, resource-bound assertions

The API verifies exact agent/device binding, organization, canonical claims,
signature, `iat`/`exp`, a bounded maximum lifetime, and an assertion ID that is
unique per agent. A replay, expiry, future clock beyond the skew window,
unknown/revoked key, signature mismatch, or mismatched tool/resource records
an unverified outcome and cannot overwrite a prior verified run.

The first wire format permits a maximum five-minute lifetime and thirty seconds
of future clock skew. Both are verifier constants, not agent-provided policy.

### D4 — Immutable run evidence separate from high-cardinality flow events

Store verified and failed assertion outcomes in a small append-only,
organization-scoped run-provenance ledger. Access events link to a verified
assertion only when the exact agent/tool/resource correlation is present; they
retain F07's existing truthful network facts otherwise. This avoids mutating
historical access events or inventing L7 tool attribution from L3/L4 traffic.

### D5 — Default-unverified UI and explicit boundaries

The agent view shows a compact run chain only for verified records. Anything
without a verified assertion is labeled **Unverified context** and never shows
an initiator name. F15 does not invoke MCP tools, enforce F14 policies, inspect
arguments/results/prompts, renew OAuth, or implement F16 approval/rate limits.

## First coherent slice

Add the versioned assertion model, canonical verifier, replay-safe persistence,
and a machine-only report endpoint. The first UI is read-only and displays the
verification outcome; no policy or proxy behavior changes. Stop the slice when
one valid assertion is persisted and rendered as verified, while signature and
replay negatives persist only an unverified result.

## Named wire-proof trigger

When a real workflow SDK signs a managed-agent assertion, prove one valid run,
one replay, and one bad signature against a disposable CP. Local tests are a
substitute until that SDK integration exists.
