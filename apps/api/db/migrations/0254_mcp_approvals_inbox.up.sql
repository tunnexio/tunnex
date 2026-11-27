-- AI-UX-1: an organization-wide Approvals inbox, and a pending request as an
-- alert event.

-- The inbox lists pending requests across every agent, newest first.
CREATE INDEX agent_mcp_tool_approval_requests_org_pending_idx
    ON agent_mcp_tool_approval_requests (org_id, requested_at DESC, id DESC)
    WHERE state = 'pending';

-- Add agent.mcp_approval_pending to alert routing and occurrence lifecycle.
ALTER TABLE alert_subscriptions DROP CONSTRAINT alert_subscriptions_event_key_check;
ALTER TABLE alert_subscriptions ADD CONSTRAINT alert_subscriptions_event_key_check CHECK (event_key IN ('agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift','gateway.offline','gateway.policy_degraded','site.link_down','device.offline','device.posture_blocked','kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable','ipsec.tunnel_down','ipsec.connection_down','ipsec.status_unavailable','agent.mcp_approval_pending'));
ALTER TABLE alert_deliveries DROP CONSTRAINT alert_deliveries_event_key_check;
ALTER TABLE alert_deliveries ADD CONSTRAINT alert_deliveries_event_key_check CHECK (event_key IN ('agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift','gateway.offline','gateway.policy_degraded','site.link_down','device.offline','device.posture_blocked','kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable','ipsec.tunnel_down','ipsec.connection_down','ipsec.status_unavailable','agent.mcp_approval_pending'));
ALTER TABLE alert_delivery_cooldowns DROP CONSTRAINT alert_delivery_cooldowns_event_key_check;
ALTER TABLE alert_delivery_cooldowns ADD CONSTRAINT alert_delivery_cooldowns_event_key_check CHECK (event_key IN ('agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift','gateway.offline','gateway.policy_degraded','site.link_down','device.offline','device.posture_blocked','kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable','ipsec.tunnel_down','ipsec.connection_down','ipsec.status_unavailable','agent.mcp_approval_pending'));
ALTER TABLE alert_occurrences DROP CONSTRAINT alert_occurrences_event_key_check;
ALTER TABLE alert_occurrences ADD CONSTRAINT alert_occurrences_event_key_check CHECK (event_key IN ('agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift','gateway.offline','gateway.policy_degraded','site.link_down','device.offline','device.posture_blocked','kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable','ipsec.tunnel_down','ipsec.connection_down','ipsec.status_unavailable','agent.mcp_approval_pending'));
