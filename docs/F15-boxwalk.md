# F15 — Signed workflow provenance box-walk

Status: **live control-plane proof complete (2026-08-21); review and CI pending**.

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

## Live control-plane wire proof

The F15 source tip was built on the control-plane test deployment and only the
API and web services were recreated. The pre-walk deployment backup is retained
at `/home/ubuntu/tunnex-backups/f15-20260821T091102Z`; the database applied
migration `0104` and both rebuilt services became healthy. The existing node
agent and managed runtime were not restarted or changed.

From the real managed runtime host, a temporary Ed25519 key was generated only
for this walk, its public half was registered through the runtime bearer
endpoint, and the following three assertions were posted. No private key,
bearer credential, OAuth secret, or MCP tool payload was retained in the
repository.

| Leg | Expected outcome | Result |
|---|---|---|
| Fresh signed assertion | `verified` ledger row and visible chain | PASS (`9769d2f8-1d82-4c69-8df0-bdee87e77acc`) |
| Exact re-submission | separate `unverified/replay` row | PASS (`a9b63fea-fe74-47fc-9155-d7a7438a138c`) |
| Same signature with changed tool claim | separate `unverified/bad_signature` row | PASS (`1351986c-947c-4f94-9528-cd3a75e7c449`) |
| Agent-detail UI | verified row shows the full chain; both unverified rows expose only reason/time | PASS (operator-captured UI evidence, 2026-08-21) |

The rendered UI shows the verified `Agent → f15-live-walk / run-live-001 →
walk.tool → mcp://walk/resource` chain. The replay and bad-signature rows
render as `Unverified context`, with workflow, tool, resource, and initiator
intentionally hidden. This walk exercised provenance recording only: no MCP
tool was invoked, no tool policy changed, and no access was granted.
