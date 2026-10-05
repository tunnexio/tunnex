# Sandboxes: decisions and story plan

Baseline: upstream/main f6d494516a8e0567aff3fd7c559e37a916ecd0d4 (v0.1.38), 2026-10-02. Source branch: story/sandbox-foundation, implemented in an isolated checkout while preserving the original checkout. No AGENTS.md or checked-in .agents/skills was found; CLAUDE.md story protocol applied. No private credential files were consulted.

## Product contract and architecture

A user opens a distinct **Sandboxes** section, creates a first-class sandbox, selects a runtime/template and optional approved skills, and connects through ordinary private SSH from their terminal or existing local Codex/Claude. Template/runtime selection is a proposal; the exact dropdown choices remain unresolved. No hosted AI, inference rerouting or MCP requirement. AI Agents remain compatible and separately listed. The pilot is not migrated.

Sandbox identity has its own ID, org ID and creating-user association. Creator association authorizes lifecycle management; it MUST NOT feed the device owner policy expansion. A network peer is an internal enrollment binding, not the product identity. Its distinct sandbox policy subject is default-deny. Desired grants must be intersected with current creator entitlement and immutable template cap at compile/reconcile time; loss of membership or entitlement withdraws grants. Existing owner/group/agent grants cannot implicitly expand sandbox access. Explicit denies, where supported by the source model, must survive; current compiler is allow-only. Deny semantics cannot be invented. Mesh/off policy mode cannot admit policy-bound sandboxes until separate enforcing isolation exists.

Reuse single-use, one-hour org/gateway/name-bound managed enrollment and separate runtime credentials internally, after separating its subject/owner semantics. No new browser CLI login protocol. v0.1.38 adds supported-host prerequisite installation and verified-download-before-redemption; prebuilt sandbox images include those dependencies at build time, bypassing per-launch installation. Split-tunnel bootstrap naturally omits DNS; future requested full-tunnel DNS must remain intact.

Rootless Podman provider on the existing approved Linux host is the first adapter. Pin image/source/digest; preload WireGuard, ip/coreutils, SSH and Python stdlib. No running systemd/DBus, host sockets or package installation at launch. Keep required resolvconf CLI. Preserve host AppArmor, routes and firewall. Provider commands take structured validated IDs, never user-supplied shell fragments. Provisioning uses durable idempotency, reconciliation and bounded cleanup; do not mark ready until current policy revision, tunnel and private SSH readiness are confirmed.

## Stories and dependency order

| Story | Deliverable and acceptance criteria | Depends on |
|---|---|---|
| S01 foundation | Distinct sandbox model, lifecycle states, immutable org/creator association, decisions and tests. No AI Agent relabeling. | baseline |
| S02 policy subject | Separate peer kind and sandbox rule projection; default-deny; no human owner/group or agent grants; requested scope bounded by current creator and template; withdrawal tested. Reject non-enforcing mode. | S01 |
| S03 authorization | Separate sandbox permissions; authenticated same-org creator operations; admin capability explicit; cross-org/non-owner refused; revoked membership refused. | S01–02 |
| S04 runtime | Provider interface and digest-pinned minimal image, preloaded essentials, unprivileged SSH account, resource caps. No per-launch installs. | S02–03 |
| S05 provision | Transactional sandbox/peer binding, idempotency, token redemption, cleanup on partial failure, readiness bound to policy revision. | S04 |
| S06 lifecycle API | Separate /sandboxes create/list/detail/start/stop/delete/status; durable CAS revisions, retry-safe operations, quotas and redacted audit. | S03–05 |
| S07 UI | Own Sandboxes navigation/list/detail/create; selection control, skills section, policy preview, progress/ready/errors, retry and copyable SSH instructions. Never exposed as AI Agent. | S06 |
| S08 skills | Approved immutable version catalog; selected/configured per sandbox; optional installation on demand; scoped egress; write-only secrets outside image/logs, explicit trust boundary. | S06–07 |
| S09 connection | Normal terminal SSH stdout/stderr/exit/file workflows; copyable local Codex/Claude instructions, no model-routing dependency. | S05–07 |
| S10 retention | Stop/start retain identity/host key and declared volume; ephemeral/delete destroys storage and revokes peer/credentials; TTL cleanup reconciles retries. | S06,09 |
| S11 controls | CPU/memory/disk and per-user/org counts; TTL, audit, visible resource/latency metrics; no secrets in read projections. | S06,10 |
| S12 validation | Local unit/integration/UI regression; actual ready-to-connect measurements and resource samples; existing agent compatibility. Live proof needs separately authorized environment. | all |

MVP: one minimal terminal template, approved skills subset, durable lifecycle, private SSH and the dedicated section. Later: more runtimes, editor adapters, richer skill catalogs, optional MCP/hosted agents, full-tunnel support. No mandatory AI stack in either phase.

## Performance and evidence

Pilot source was v0.1.37, not this baseline. Single samples: ~218 MB unpacked preloaded image, ~10 MB idle memory under 256 MiB cap; stop 0.920 s, warm Podman start 0.102 s; Mac control trigger to private SSH 8.590 s including control connection/polling. These are feasibility observations, not percentiles. Parent-reported final pilot checks passed: SFTP upload, command transformation and download; stop/start retained identity, pinned host key and file. Final samples: stop 0.255 s, provider start 0.107 s, control trigger to SSH plus file confirmation 8.717 s. These were not rerun here. Pilot retains inherited Owner access and native public egress; rootless containers share the host kernel. Product policy isolation and private-path enforcement are separate implementation requirements, not established by the pilot.

Proposed initial budgets: essential image <=250 MB unpacked; idle <=32 MiB with 256 MiB default cap; warm click-to-private-SSH p95 <=10 s on preloaded host. Record API admission, provider start, enrollment, policy acknowledgement and SSH readiness separately over at least 30 starts before accepting/revising budgets. Cold pull is separately measured; no instant-start guarantee.

## Current slice and remaining decisions

Start S01 with a pure distinct domain model and legal lifecycle transitions. Add an enforcing-mode compiler guard so future sandbox-kind peers cannot acquire legacy owner or agent grants; this is preparatory and does not create sandbox peers. S02 must wire durable kind/storage, bounded grants, destination isolation and mode admission before production creation. No migration/API/UI/provider is claimed delivered by this slice.

Unresolved: final templates/selection choices, skills catalog and approval authority, persistence default/TTL, organization quota defaults, community/enterprise availability, exact packet-scope intersection across dynamic FQDN/Kubernetes destinations. Paper these before dependent slices; fail closed until resolved.

No push/merge/deployment, live host/account/policy operations or stopped security-audit retries. Local feature tests are distinct from that audit. Full gates and live box-walk remain pending; unit tests do not constitute wire proof.
