# MCP OAuth refresh walk — 2026-09-12

Status: in progress, not passed.

Source main: 1ed535ea (PR71). CP services healthy; retained test agent43.205.122.116 / device01a090c2-d5e5-7c66-99b3-a56038bf9361 active. No new AWS resources.

Previous Cloudflare grant was revoked during authorized cleanup. New profile oauth-refresh-walk-20260912 points to https://bindings.mcp.cloudflare.com/mcp; replacement preview affects only one member of ai-mcp-walk-20260911. Restore its original profile http://172.31.24.146:8080/mcp after proof. Preserve existing tool policy and credentials; no upstream write tool is part of this test.

Acceptance: initial authorized read-tool success, natural token lifetime elapses, automatic runtime lease refresh without interactive consent, advanced expiry and subsequent read-tool success. No manual database expiry rewrite qualifies as natural refresh. Record metadata only; never tokens.

Checkpoint: profile replacement applied; runtime observed the Cloudflare protected resource at2026-09-12T04:56:18Z. Existing lab runtime SHA2569e4f71cd7e27cb52d2e191ce63e022dab1ec38e5fa97d4ba81d29e3908a2d1de. New consent reached iotunnex@gmail.com / Iotunnex@gmail.com's Account with User Read, Account Read, offline access, Workers Write and D1 Write. Authorize click rejected by automatic approval review; exact scope approval requested. No new provider grant, no token expiry, no refresh proof yet. Profile remains assigned to lab group while consent is pending; original echo assignment is retained in history. No runtime binary/credential changes.
