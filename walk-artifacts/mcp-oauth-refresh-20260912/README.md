# MCP OAuth refresh walk — 2026-09-12

Status: in progress, not passed.

Source main: 1ed535ea (PR71). CP services healthy; retained test agent43.205.122.116 / device01a090c2-d5e5-7c66-99b3-a56038bf9361 active. No new AWS resources.

Previous Cloudflare grant was revoked during authorized cleanup. New profile oauth-refresh-walk-20260912 points to https://bindings.mcp.cloudflare.com/mcp; replacement preview affects only one member of ai-mcp-walk-20260911. Restore its original profile http://172.31.24.146:8080/mcp after proof. Preserve existing tool policy and credentials; no upstream write tool is part of this test.

Acceptance: initial authorized read-tool success, natural token lifetime elapses, automatic runtime lease refresh without interactive consent, advanced expiry and subsequent read-tool success. No manual database expiry rewrite qualifies as natural refresh. Record metadata only; never tokens.
