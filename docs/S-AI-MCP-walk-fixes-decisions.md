# AI/MCP walk fixes

User approved fixing observed bugs and continuing the live walk on 2026-09-11.

- Locked: correct UI permission identifiers against generated RBAC; preserve server authorization.
- Locked: MCP profiles show observed tools, their source agent and freshness; never imply profile creation alone proves discovery or enforcement. Reuse per-agent inventory APIs.
- Locked: expose useful missing-resource guidance in policy templates; support API-authorized destination selection without inventing permissions.
- Locked: explain runtime capability/opt-in prerequisites before bootstrap. Preserve paid entitlement and default-off opt-in.
- Locked: investigate opt-in recovery and OpenAI completion-token compatibility from evidence before changing behavior. Do not retry revoked credentials or weaken authentication.
- Locked: use configured models for agent policy selection rather than requiring model-ID discovery elsewhere.
- Locked: preserve existing deployed VPN identity/URL changes as local dependencies. New branch starts at current origin/main d378e332, then includes approved deployed story/ai-vpn-identity history.
- Deferred: third-party OAuth proof requires an actual configured provider; synthetic echo proof is labelled as such.

Verification: targeted regression tests, relevant web/API/CLI gates, then isolated AWS agent live allow/deny, model inference and template walk. No unrelated root working-tree edits. No merge or release requested.

Continuation: the live walk exposed an argument-constraints placeholder that omits the OpenAPI-required properties field. Locked: show a contract-valid example, reject missing required/properties locally with actionable guidance, and retain server-side validation. Do not broaden the supported constraint language. Network enforcement remains Off in Demo; its zero-rule confirmation warns all traffic would be denied. Separate network-walk scope is pending user disposition.
