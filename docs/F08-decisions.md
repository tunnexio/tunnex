# F08 — Read-only Test Access diagnostics decisions

Status: **IMPLEMENTED / CORE LIVE WALK PASS / MEMBER-SESSION LEG PENDING**.

## Customer outcome

An authorized operator selects one managed agent and enters a destination,
protocol and port. Tunnex returns one ordered, server-owned explanation of the
path and the first exact blocker without changing policy, runtime state, routes,
DNS, credentials or the data plane.

## Reuse census

- Canonical agent identity/lifecycle/owner remains `devices` plus
  `agent_profiles` (F01/F06). No diagnostic identity table.
- Runtime desired/applied/freshness/health remains `agent_runtime_state` through
  the F04 status service. No second liveness clock.
- Gateway reporting and applied policy health remain the node/status seams used
  by the released gateway and agent lists.
- The enterprise policy compiler remains the only authorization truth. F08
  evaluates the exact compiled artifact for the agent's assigned gateway; it
  does not re-read rules into a parallel authorization model.
- Resource protocol/ports, temporary-rule expiry and F07 policy hash/version
  remain the existing stored/compiled facts.
- F06 `agent:view_privileged` is the authorization boundary. No new permission
  and no role-name inference in the handler or UI.

## Locked decisions

### D1 — One GET, no state and no hidden write

Add a GET route scoped by organization and agent. Inputs are destination,
protocol and port query parameters. The evaluator performs no insert, update,
delete, push, poll, wake, DNS query or network connect. Repeating a request over
unchanged state is byte-equivalent except for observation timestamps.

### D2 — Ordered tri-state checks, not a synthetic score

Each check is `pass`, `fail` or `inconclusive` and carries a stable machine code
plus concise operator copy. The response order is:

1. agent identity and lifecycle;
2. runtime configuration revision/freshness;
3. assigned gateway reporting/readiness;
4. destination parsing and DNS observability;
5. route ownership;
6. compiled policy and matching grant/expiry;
7. applied-policy revision/hash agreement.

Overall is `allowed` only when every required check passes, `denied` when an
authoritative fail exists, and `inconclusive` when no fail exists but Tunnex
does not own enough evidence. The first blocker is the first fail, otherwise the
first inconclusive check. Later checks remain visible when they are independently
answerable; they are not fabricated from the first result.

### D3 — The compiler artifact is the policy oracle

Match the source agent's canonical tunnel address against the exact compiled
artifact for its assigned gateway, then match destination IP, protocol and port
using the same prefix/protocol/port semantics as the node agent. Return the
matched rule ID and compiled policy hash/version when present. Expired,
disabled, deleted or non-applicable rules cannot be described as active grants.

No address-to-agent inference is allowed. Identity comes from the selected
device and the artifact's F07 subject attribution.

### D4 — DNS honesty

A literal IP makes the DNS check `pass/not_applicable`. For a hostname, the CP
must not resolve with its own resolver and call that the agent's answer. Until a
signed/runtime-reported agent-side DNS observation exists, hostname evaluation
is `inconclusive` with `agent_dns_not_observed`; route/policy checks that require
an IP are also inconclusive. The UI asks for a resolved IP to continue.

### D5 — Route means configuration intent, not a ping

Route evaluation uses the agent's current desired configuration and the
gateway's finalized compiled route intent. It never treats a policy allow as
proof that a kernel route or cloud fabric works. A matching configured route is
`pass`; missing intent is `fail`; cloud/VPC reachability beyond Tunnex-owned
state is `inconclusive` and named as such.

### D6 — Privileged information stays scoped

Organization membership is checked before edition. Then reuse the F06 scoped
`agent:view_privileged` decision for the selected agent. Known, missing and
foreign agents return the same telemetry-free forbidden/not-found boundary
already used by agent profile/runtime status. The released route is absent for
unrelated members and clears all diagnostic state synchronously on org switch.

### D7 — Active probe is deferred, not faked

F08 ships the read-only evaluator only. The repository has no authenticated,
bounded agent command channel; adding one to perform a TCP/DNS probe would be a
new remote-execution and SSRF surface larger than this story. A future **F08b —
bounded agent probe** may add an explicit org opt-in default OFF, destination
allowlist, strict timeout/byte cap, no redirects, audit and runtime-side result
signing. Unit tests or a CP-side DNS/connect attempt never substitute for it.

### D8 — No schema migration

All inputs are current canonical state. F08 adds OpenAPI DTOs, a pure evaluator,
service orchestration, one HTTP route and one released UI panel. No table,
column, queue, history row or cached verdict is added.

## UI contract

- Test Access lives on Access Policies and reuses the existing agent/resource
  lists. A custom destination field accepts an IP or hostname; protocol is
  TCP/UDP and port is required.
- The result is an ordered checklist with the first blocker called out. It shows
  only server-returned facts and labels inconclusive evidence explicitly.
- It never offers an Apply, Fix, Create rule or Probe action. Existing policy
  mutation surfaces remain separate.
- Late responses from a prior organization or prior input tuple cannot commit.

## Optimized DEV walk contract

F08 also adds a reusable `scripts/ai-agent-dev-walk.sh` harness for F08+ stories.
The harness does not contain credentials and does not make product decisions.
It standardizes four operations:

1. `preflight`: exact clean content SHA, component diff, CP/VM disk, schema,
   health/restarts, protected handoff paths and rollback inventory;
2. `prepare`: story-prefixed remote scratch and redacted evidence templates;
3. `verify`: exact deployed revision labels/digests, schema and service health;
4. `cleanup-check`: story-prefix DB/API absence, five managed VM paths,
   reporter/container scratch and any declared temporary SG rule.

The harness builds/deploys only components changed by the frozen commit. API/web
stories reuse an existing healthy DEV gateway; node stories use one documented
reusable reporter fixture. Secret-bearing bootstrap execution remains an
explicit user-authorized step and is never embedded in the harness or artifacts.

## Observable acceptance

- active/fresh agent + healthy gateway + matching compiled grant returns
  `allowed` with the exact rule and applied policy/config facts;
- the same tuple without a grant returns `denied/no_matching_grant`;
- suspended/revoked, stale runtime, offline gateway, missing route, expired
  grant and hostname-without-agent-DNS each name their own truthful blocker;
- an unrelated member receives no privileged diagnostic fact and no released
  diagnostic DOM;
- rapid org/input switching cannot render stale agent, destination or result;
- repeated evaluations change no database row, desired revision, policy hash,
  gateway state or runtime state;
- the optimized harness records provenance, verifies rollback readiness and
  proves scoped cleanup without retaining a secret.

## Explicit non-goals

- no active TCP/UDP/ICMP/DNS probe and no remote command channel (F08b);
- no policy mutation, suggested auto-fix or one-click grant;
- no packet capture, traceroute, cloud route-table API or inferred fabric pass;
- no cached verdict/history/alert (F11) and no MCP/tool diagnostics (F12+);
- no new permission, ownership model, agent group or policy template (F09).

## Implementation ledger

- OpenAPI owns the one read-only route and bounded diagnostic DTOs; generated
  Go/TypeScript bindings are checked in from repository-pinned generators.
- The node service evaluates the selected tuple against its exact finalized
  gateway artifact, reusing the same topology batch, active-hub choice,
  `finalizeArtifact`, pushed hash and applied hash as desired-state health.
- Runtime route intent is derived read-only from the same canonical rows as
  managed polling; no poll, report, wake or revision mutation occurs.
- The released Access page scopes the agent list through existing privileged
  profile access, ignores stale org/input responses and renders server facts.
- `scripts/ai-agent-dev-walk.sh` implements only the secret-free inventory,
  provenance and cleanup checks locked above; deployment and credentials remain
  outside it.
