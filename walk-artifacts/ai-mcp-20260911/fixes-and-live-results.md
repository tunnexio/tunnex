# Approved fixes and resumed wire walk — 2026-09-11

Branch story/ai-mcp-walk-fixes starts from freshly fetched origin/main d378e332, retaining previously deployed VPN story history. Root dirty checkout untouched. Decision commit a8cd1d7f. Fixes8d8c90af,95e6d94d,e925dec9. No push/PR/merge/release.

## Fixed and deployed

- Actual generated MCP policy/approval permission names used; owner controls accessible.
- First-policy not-found is an empty deny-all authoring state, not a loading failure. Other failures stay errors.
- MCP profile page displays observed tools/descriptions/schema/server status, reporting-agent context and timestamp. Different-profile/group mismatch has explicit navigation. Permission link opens MCP tab.
- Managed bootstrap blocked in actual roster flow while org runtime off, with prerequisite/paid-plan settings guidance. Revoked/unauthorized runtime retry behavior intentionally unchanged.
- Configured-model picker added to team policy editor.
- Policy-template empty destination state links to Resources; clearer network-access wording.
- Single-port resource payload supplies matching port bounds (API requires both).
- Chat max_completion_tokens normalized to existing bounded max_tokens field; conflicting and invalid limits rejected, existing4096 ceiling retained.

## Validation

Final web126 files /1512 tests pass. Web production build pass. Complete aigateway package tests pass in both editions; affected Agent/AI HTTP tests pass in both editions; API open build and Linux enterprise build pass. No DB migrations changed or applied; full DB-backed composite/CI not claimed.
Independent read-only review: two navigation findings fixed; follow-up first-policy and port fix no actionable regressions. No universal security review claim.

## Live proof

CP15.206.183.232 API healthy tunnex-api:ai-mcp-8d8c90af; web healthy tunnex-web:ai-mcp-e925dec9; HTTPShealthz200. Artifact SHA256 verified before deploy. Only API/web recreated; nginx reloaded. Rollback ai.override.yml retained mode600 at /home/ubuntu/tunnex/ai-mcp-fixes-20260911/rollback-ai.override.yml.

Chrome rendered MCP profile shows echo/restricted_echo with healthy source server and observation timestamp. Owner first-policy controls verified.

- Allow echo only: local runtime MCP proxy echo200 WALK_OK; restricted_echo403; upstream counters {echo:1}.
- Remove echo permission: echo403; upstream counters unchanged {echo:1}.
- Grant test agent model access, exchange current runtime identity for short-lived AI credential in memory: max_completion_tokens512 request200 WALK_OK.
- Prior ungranted model403 and disabled issuance403 documented in checkpoint.
- Resource172.31.24.146/32 TCP8080 created using equal range workaround before patch; subsequently saved through fixed Single port UI successfully.
- Template v1 created, preview reported1 agent/1 new rule/0 gateways. Assignment applied, then removed through UI. This proves authoring lifecycle, NOT transit enforcement: destination is test agent's own host and preview reported no changed gateways.

## Retained limits/state

Test host and fixture remain running/billable. Runtime/MCP opt-ins enabled. Test MCP policy has zero allowed tools after withdrawal proof. Test AI assignment re-enabled for compatibility proof. Test group/profile/template/resource retained; template assignment removed.
Third-party OAuth, approval-consumption/rate/argument live tests, template transit dataplane and broad multi-destination policy authoring remain unqualified. Fixture has two synthetic echo tools, not a third-party integration. UI improvements here do not imply universal MCP compatibility.
