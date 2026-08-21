# F15 — Signed workflow provenance box-walk

Status: **local proof complete; live control-plane walk deferred**.

## Local, production-shaped proof

An isolated disposable PostgreSQL instance was migrated from an empty database
through F15 migration `0104`. The integration test then enrolled one
device-bound Ed25519 public key and submitted the same signed assertion through
the service boundary.

| Leg | Expected outcome | Result |
|---|---|---|
| Valid signature, fresh one-use assertion | Immutable `verified` record and a visible chain | PASS |
| Repeat of the same assertion ID | Separate `unverified/replay` record | PASS |
| Signed claim tampered after signing | Separate `unverified/bad_signature` record | PASS |
| Read projection for unverified evidence | No workflow/run/tool/resource/initiator chain | PASS |
| Direct ledger deletion | Database rejection | PASS |
| Organization deletion | Ordinary foreign-key cascade remains possible | PASS |

The web component test separately proves that a verified row displays the
Agent → Run → Tool → Resource chain, while an unverified row renders only its
verification reason and received time. The UI has no MCP invocation or policy
action.

## Deferred live wire proof

Trigger: F14's prerequisite migration is merged and a real managed workflow
runtime/SDK emits an F15 assertion on a control-plane test deployment. The
walk must register the runtime's public key, post valid/replayed/tampered
assertions through the runtime bearer endpoint, and capture the agent-detail
screen. This is a wire proof, not substituted by the local test above.
