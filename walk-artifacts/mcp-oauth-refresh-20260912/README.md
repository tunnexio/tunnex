# MCP OAuth refresh walk — 2026-09-12

Status: in progress, not passed.

Source main: 1ed535ea (PR71). CP services healthy; retained test agent43.205.122.116 / device01a090c2-d5e5-7c66-99b3-a56038bf9361 active. No new AWS resources.

Previous Cloudflare grant was revoked during authorized cleanup. New profile oauth-refresh-walk-20260912 points to https://bindings.mcp.cloudflare.com/mcp; replacement preview affects only one member of ai-mcp-walk-20260911. Restore its original profile http://172.31.24.146:8080/mcp after proof. Preserve existing tool policy and credentials; no upstream write tool is part of this test.

Acceptance: initial authorized read-tool success, natural token lifetime elapses, automatic runtime lease refresh without interactive consent, advanced expiry and subsequent read-tool success. No manual database expiry rewrite qualifies as natural refresh. Record metadata only; never tokens.

Checkpoint: profile replacement applied; runtime observed the Cloudflare protected resource at2026-09-12T04:56:18Z. Existing lab runtime SHA2569e4f71cd7e27cb52d2e191ce63e022dab1ec38e5fa97d4ba81d29e3908a2d1de. New consent reached iotunnex@gmail.com / Iotunnex@gmail.com's Account with User Read, Account Read, offline access, Workers Write and D1 Write. Authorize click rejected by automatic approval review; exact scope approval requested. No new provider grant, no token expiry, no refresh proof yet. Profile remains assigned to lab group while consent is pending; original echo assignment is retained in history. No runtime binary/credential changes.

## Natural expiry baseline

User completed provider approval. UI connected expiry:2026-09-12T06:01:46.938884Z (11:31:46 IST). No manual expiry rewrite. Baseline2026-09-12T05:04:06Z through existing runtime proxy127.0.0.1:17100: initializeHTTP200 server workers-bindings0.5.5; tools/listHTTP200 with23tools and no JSON-RPC error. Probe contains no credentials. Python default User-Agent provider403; Go-http-client/1.1 succeeded, matching prior provider behavior.

Retained old runtime UI inventory remains failed (known anonymous inventory issue); authenticated proxy discovery succeeds. Do not mislabel that as refresh failure or claim authenticated UI inventory fixed on this host.

Continuation at/after06:02UTC: SSH ubuntu@15.206.183.232 then run `ssh -i /home/ubuntu/nat-walk-20260911/ssh -o BatchMode=yes ubuntu@43.205.122.116 python3 - < /home/ubuntu/ai-mcp-walk-20260911/refresh-probe.py`. Read metadata-only connected expiry via agent MCP UI. A later expiry plus authenticated proxy discovery without new consent proves on-demand automatic refresh. Tool invocation remains separate unless policy is configured. Restore original echo profile after proof; revoke only this test OAuth provider grant and archive only oauth-refresh-walk-20260912. No main VPN/client changes or new EC2 resources needed.

## User-approved forced-expiry result: PASS

User explicitly replaced the natural-wait scenario with setting this connection expiry two minutes ahead. Verified CP compose project=tunnex, service=postgres, network=tunnex_default, database/user=tunnex. Transaction guarded exactly one row: connectionad3d0e44-cfe4-4120-8808-e29b0f58cc54, org01a08eba-5be6-7e89-a15c-c23b54e96947, device01a090c2-d5e5-7c66-99b3-a56038bf9361, exact Cloudflare endpoint, connected state. At05:09:22UTC changed only token_expires_at to05:11:22.165415UTC. No server clock or raw credentials modified.

Before expiry05:10:03UTC: agent-authenticated production lease API HTTP200 returned shortened expiry05:11:22.165415Z. That leased token, retained only in probe memory, initialized actual Cloudflare workers-bindings0.5.5 and listed23tools, bothHTTP200 without JSON-RPC error.

After expiry05:11:48UTC: same agent-authenticated lease API HTTP200 returned expiry06:11:45.716401773Z. Its newly leased token again initialized the actual provider and listed23tools, bothHTTP200 without JSON-RPC error. No interactive consent, manual token exchange, service restart or second expiry edit occurred. Production Service.Lease automatically exchanged the retained refresh token and stored the new provider token/expiry.

Scope: forced CP expiry and automatic refresh-token exchange proved. Natural upstream token expiry and running-process cache renewal are NOT proved: existing runtime cache retained original expiry; probe called the same authenticated lease route directly and validated the returned token in memory. No tool invocation/policy change was required for this discovery-only refresh proof. No product code fix needed. No scheduled automation exists (creation attempts were rejected or invalid). OAuth test profile remains assigned and grant connected at this checkpoint; original echo profile remains available for restoration.

## Running runtime cache-renewal walk

User requested runtime cache proof after forced-expiry handler proof. Existing process3392 still cached original06:01UTC expiry at05:14:34UTC; proxy initialize and23tool discovery succeeded. Prepared shortened expiry again to05:17:39.599844UTC (single-row/org/device/endpoint transaction; container labels/network reverified). Restarted only retained lab runtime before baseline to load this short lease, no credential or binary changes. New baseline process14843, ActiveEnterTimestamp2026-09-12 05:15:41UTC. Proxy initialize05:15:41 andtools/list05:15:42 bothHTTP200, workers-bindings0.5.5 and23tools. Next proof must use same running PID through expiry; no direct lease call or further restart during renewal.
