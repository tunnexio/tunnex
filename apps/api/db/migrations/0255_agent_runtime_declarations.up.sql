-- AI-UX-1: two more things a managed runtime tells the control plane about
-- itself. Both are nullable; a runtime that predates them says nothing and
-- nothing changes for it.

ALTER TABLE agent_runtime_state
    -- When the runtime last declared (poll query mcp_hold=true) that it keeps an
    -- MCP call open while an "Ask first" request waits for an approver. NULL = a
    -- runtime that gives up after ten seconds, so its calls are never held.
    ADD COLUMN mcp_hold_capable_at timestamptz,
    -- Whether the runtime wrote the pushed DNS servers into its tunnel
    -- configuration. false = the host has no resolvconf, the DNS line was left
    -- out, and private DNS names pushed through the tunnel do not resolve there.
    -- NULL = the runtime did not say.
    ADD COLUMN tunnel_dns_applied boolean;
