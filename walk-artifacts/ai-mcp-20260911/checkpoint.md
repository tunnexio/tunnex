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

## Scale continuation — 2026-09-11

User installed Scale and asked to continue. Runtime opt-in remained off (poll401); enabled through Settings > AI Agents. The earlier401 caused the service to exit successfully; restarted only the isolated test agent service. Customer-facing recovery after opt-in remains a UX finding.

### Live PASS

- Authenticated poll200 revision1 after opt-in.
- WireGuard runtime interface created. UI reports connected, ready, applied1/desired1.
- Group membership verified: one member. Agent inherited the group's private MCP endpoint. Inventory healthy with echo and restricted_echo, input schema hashes recorded by CP.
- Both unapproved tools invoked through local MCP proxy127.0.0.1:17100 returned403, code-32100. Fixture /counts remained{}: no denied call reached upstream.
- Scoped test team model policy saved revision1 and agent assignment applied desired1/applied1/team1.
- Runtime identity exchanged for ephemeral AI credential (201); credential remained process-memory only, not printed.
- Ungranted model request403 ai_policy_denied, request183eaddebe483bbb11b6343258794101.
- Granted custom-39e11fc9-f668-45b1-8a16-ba7625d09e49/gpt-5 returned200 with WALK_OK using max_tokens512.
- Disabled only the test agent AI assignment; new credential issuance403 ai_policy_denied (90c01ee6cb6373f66355f5cdc6b07ec5).
- Created disposable policy template ai-mcp-walk-20260911 through UI. No network rules assigned.
- Audit UI shows named Control Plane Admin for runtime opt-in, group membership, MCP assignment, model-policy/assignment updates and template creation.

### Concrete failures / unproven paths

- P1: AgentDetail.tsx uses agent:mcp_tool_policy:manage and agent:mcp_tool_approval:approve, whereas generated RBAC has agent_mcp_tool_policy:manage (and corresponding underscore approval permission). Owner sees denied UI. Allowed-tool and approval paths cannot be completed through shipped UI until fixed. No RBAC bypass used.
- Policy-template New version shows empty Destination resource selector and no create-resource next step. Template version/preview/apply/withdraw remains unproven; no existing destinations were present. UI only authors one resource while API supports multiple destination kinds.
- max_completion_tokens request returned400 for both model paths; max_tokens request succeeds. Compatibility investigation remains; no claim of arbitrary OpenAI payload compatibility.
- One pre-existing node.enrolled audit event lacks actor; not generated by this agent walk.
- OAuth, step-up, tool rate/argument constraints, allowed MCP invocation, issued-token revocation latency and policy-template dataplane proof remain unproven. No universal green claim.

### Retained state

Runtime and MCP opt-ins enabled. Test agent healthy; its AI access intentionally disabled after refusal proof. Test group, MCP profile and empty policy template retained. Isolated AWS host still running/billable for follow-up. No product changes, UI patches, push or release performed in this continuation. Findings held for user disposition as requested.
