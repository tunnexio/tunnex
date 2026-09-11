# AI Agent / MCP live walk — 2026-09-11

Status: INCOMPLETE, runtime capability gate blocks wire proof.

## Verified live

- Approved isolated EC2 i-03e7016193a694f8f: t3.small, encrypted 16GB, private 172.31.24.146. SG sg-010048c5675a3f8da admits SSH from CP public IP only and MCP8080 from CP private IP only. AWS CLI ran on CP.
- Standard UI-generated v0.1.27 signed bootstrap enrolled test agent 01a090c2-d5e5-7c66-99b3-a56038bf9361, address 10.99.0.3. Runtime service and loopback MCP proxy start; WireGuard interface does not apply.
- Ubuntu26.04 already has resolvconf; openresolv package unavailable. Installed wireguard-tools, jq, curl and locally built releaseverify prerequisite.
- Bootstrap hostname initially did not resolve. Test host-only /etc/hosts maps internal.tunnex.app to CP private IP 172.31.25.55. Health HTTPS200. This accommodation does not prove customer bootstrap DNS automation.
- Harmless HTTP MCP fixture exposes echo and restricted_echo on private8080, with upstream call counters. No actual agent-mediated tool call proven yet.
- MCP management enabled; test MCP profile and agent group created, profile assignment submitted. Group membership was submitted but agent detail still shows Managing group None: propagation/semantics require verification.
- Real authenticated runtime poll returns503. Agent Runtime UI says managed agent runtime synchronization is temporarily unavailable.
- Licence & plan UI confirms Community. Production OrganizationOptIn returns unavailable when tier is Community (apps/api/cmd/server/main.go); runtime handler maps this to503. No entitlement bypass or runtime opt-in change performed.

## Ranked findings held for disposition

1. Blocking onboarding inconsistency: UI permits standard managed bootstrap on Community, but its runtime is unavailable by plan. Generic503 and active roster conceal the prerequisite. Need product decision on entitlement versus preflight/explanation before changing code.
2. Bootstrap prerequisite/DNS journey requires operator knowledge on a fresh host. Show and validate prerequisites before issuing command.
3. Policy template UI exposes one resource per version, while OpenAPI accepts multiple items and resource/group/site/k8s_service destinations. Capability/UI gap identified from source, not wire-tested.
4. Policy template wording (immutable versions, access intent) lacks a concrete use case and guided first template flow.

Policy templates represent reusable versioned network access intent assigned to agent groups with impact preview. They are distinct from model grants and MCP tool permissions. Live page loads its empty state successfully; assignment and network enforcement are not yet proven.

## Pending

Resolve runtime entitlement decision; verify group membership/readback; MCP inventory, allowed/denied calls with upstream counters; model grant inference; audit; policy-template assignment and withdrawal.

Test infrastructure remains running and billable for continuation. No cleanup performed. No credentials or private bootstrap artifacts are included in this evidence.
