# Network and OAuth continuation — 2026-09-11

User authorized completing the remaining walk and required isolated infrastructure. No main merge or public release.

Disposable organization AI network walk 20260911 created through existing CP-admin session; selected through Settings organization selector. Current user temporarily gains second membership (simple /ai/v1 may require explicit-org URL until cleanup). Demo policy unchanged.

AWS operations executed only through CP ubuntu@15.206.183.232. New gateway i-0765980443390d99b, public3.6.210.102/private172.31.25.166; new agent i-0d2265341cfba2a78, public13.205.1.253/private172.31.27.79. Both Ubuntu26.04/t3.small/encrypted16GBgp3/IMDSv2required. SGsg-083b3b8b6a37acb55 SSH fromCPpublic/32, UDP51820 from test sources only. Gateway source/destcheck disabled. Original fixture instance43.205.122.116 remains untouched.

Automatic approval rejected replacing original fixture runtime credentials/stopping its tunnel because target identity and disruptive scope were insufficiently clear. Rejected command did not run. Safer alternative: fresh disposable agent instance, bootstrap asserts no existing credential. No workaround against rejected target.

Gateway01a0913c-9e9e-7b2c-88ba-c86be6458eb3 enrolled using UI pinned image digest28c3e14afab6ae3c896649b9328323b6d42d4208da090f9ab0d00f0ef9312a52 (v0.1.27). New agent signed bootstrap exit0/serviceactive, WireGuardhandshake. Source10.99.0.2. Gateway private endpoint172.31.25.166:51820. Newhost /etc/hosts maps CPname to172.31.25.55; artifact verifier installed.

Site network-proof-private publishes172.30.250.0/30. Gateway test namespace ai-proof-target contains172.30.250.2 with HTTP8080 and8081 via veth; return route via172.30.250.1. Resource proof-http is172.30.250.2/32 TCP8080. Group network-proof-group contains network-proof-agent. Template private-http-access v1 references proof-http. Isolated org enforcement enabled from Off/zero rules. Live traffic result pending.

OAuth: Cloudflare official bindings MCP discovery and dynamic client registration succeeded from CP using curl. ClientIDoBGGrxTZlbwr3WGN, public-client auth none, callback https://internal.tunnex.app/api/v1/mcp/oauth/callback. Registration document retained mode600 on CP; no token minted yet. Python urllib metadata requests403 while curl200; distinguish transport behavior. Real consent/inventory/tool call remains pending.

New UI finding: runtime opt-in toggled On in settings but subsequent SPA Add Agent showed stale Off dialog; full navigation refreshed authoritative state and allowed enrollment. No fix yet in this continuation.
