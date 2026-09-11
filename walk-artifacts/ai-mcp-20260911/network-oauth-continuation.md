# Network and OAuth continuation — 2026-09-11

User authorized completing the remaining walk and required isolated infrastructure. No main merge or public release.

Disposable organization AI network walk 20260911 created through existing CP-admin session; selected through Settings organization selector. Current user temporarily gains second membership (simple /ai/v1 may require explicit-org URL until cleanup). Demo policy unchanged.

AWS operations executed only through CP ubuntu@15.206.183.232. New gateway i-0765980443390d99b, public3.6.210.102/private172.31.25.166; new agent i-0d2265341cfba2a78, public13.205.1.253/private172.31.27.79. Both Ubuntu26.04/t3.small/encrypted16GBgp3/IMDSv2required. SGsg-083b3b8b6a37acb55 SSH fromCPpublic/32, UDP51820 from test sources only. Gateway source/destcheck disabled. Original fixture instance43.205.122.116 remains untouched.

Automatic approval rejected replacing original fixture runtime credentials/stopping its tunnel because target identity and disruptive scope were insufficiently clear. Rejected command did not run. Safer alternative: fresh disposable agent instance, bootstrap asserts no existing credential. No workaround against rejected target.

Gateway01a0913c-9e9e-7b2c-88ba-c86be6458eb3 enrolled using UI pinned image digest28c3e14afab6ae3c896649b9328323b6d42d4208da090f9ab0d00f0ef9312a52 (v0.1.27). New agent signed bootstrap exit0/serviceactive, WireGuardhandshake. Source10.99.0.2. Gateway private endpoint172.31.25.166:51820. Newhost /etc/hosts maps CPname to172.31.25.55; artifact verifier installed.

Site network-proof-private publishes172.30.250.0/30. Gateway test namespace ai-proof-target contains172.30.250.2 with HTTP8080 and8081 via veth; return route via172.30.250.1. Resource proof-http is172.30.250.2/32 TCP8080. Group network-proof-group contains network-proof-agent. Template private-http-access v1 references proof-http. Isolated org enforcement enabled from Off/zero rules. Live traffic result pending.

OAuth: Cloudflare official bindings MCP discovery and dynamic client registration succeeded from CP using curl. ClientIDoBGGrxTZlbwr3WGN, public-client auth none, callback https://internal.tunnex.app/api/v1/mcp/oauth/callback. Registration document retained mode600 on CP; no token minted yet. Python urllib metadata requests403 while curl200; distinguish transport behavior. Real consent/inventory/tool call remains pending.

New UI finding: runtime opt-in toggled On in settings but subsequent SPA Add Agent showed stale Off dialog; full navigation refreshed authoritative state and allowed enrollment. No fix yet in this continuation.

Network proof: template preview with enforcing On reported1agent/1rule/1gateway changed (Off previously0gateways). Apply succeeded; agent automatically learned172.30.250.2 route through runtime/source10.99.0.2. curl8080 returnedHTTP200 TUNNEX_TEMPLATE_NETWORK_OK; curl8081 timed out, although both8080and8081 returned the marker directly from gateway. Thus same-routed-destination port denial is real dataplane evidence. Removal UI left0assignments; gateway nft tunnex.forward had no allow rule and default drop; runtime removed destination route; subsequent8080 curl timedout/HTTP000. No manual client route/policy edits were used. Agentid01a09145-096b-7b06-a735-bbdc6e87e9df. Original Demo untouched.

## Enrollment prerequisite fix and live deployment (2026-09-11)

- Product commit `98791fdf`: Add Agent reads current organization runtime prerequisites before permitting bootstrap. Unknown/read-error state refuses token issuance and supports Retry; stale cached On/Off no longer controls enrollment. Successful retry clears a previous gateway-read error.
- Validation: web typecheck, full web suite (126 files / 1516 tests), and production build passed before the review's small gateway-error reset. After that reset, all 6 focused enrollment tests and production build passed again. No API/schema changes in this slice.
- Deployed web artifact SHA256 `f80a145c73e17095d65a34ab74538ee3ec806070463e01fb27cf48c875eb3ac9` to CP; image `tunnex-web:ai-mcp-98791fdf`. API and web both healthy. HTTPS health succeeds with CP address explicitly resolved; this is not a claim about CP host DNS.
- Browser verification: Add Agent displays Step 1 with the active `ai-network-walk-gateway`; cancelled without issuing another credential. Stale On/Off and unreadable/retry cases are regression-test evidence, not live configuration toggles.
- Rollback retained at `/home/ubuntu/tunnex/ai-mcp-fixes-20260911/rollback-before-runtime.yml` (restricted permissions).

## Remaining OAuth consent boundary

- Runtime discovered the real Cloudflare Bindings protected resource and the browser reached its real OAuth consent screen for client `Tunnex MCP verification`, redirecting to this CP.
- Automatic approval review rejected clicking Approve because the external account/client/scopes had not been specifically authorized. No consent grant or refresh token was obtained. A user question requesting account identification and approval for `user:read account:read offline_access` is pending.
- OAuth inventory, authenticated tool execution, refresh and revoke are NOT proven by reaching the consent screen.
- Disposable organization `AI network walk 20260911` and instances `i-0765980443390d99b` / `i-0d2265341cfba2a78` remain for the pending OAuth proof. Cleanup remains outstanding; the temporary second org membership remains and may affect org-less SDK resolution. Original Demo infrastructure is preserved. After OAuth proof, remove the disposable test resources and membership and terminate these two instances.
- Branch is local; no push, merge, or release claimed.
