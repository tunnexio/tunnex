-- Refuse rollback while static key alert data exists; never delete history.
-- (Re-adding the narrower constraint fails on such a row.)
ALTER TABLE alert_subscriptions DROP CONSTRAINT alert_subscriptions_event_key_check;
ALTER TABLE alert_subscriptions ADD CONSTRAINT alert_subscriptions_event_key_check CHECK (event_key IN ('agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift','gateway.offline','gateway.policy_degraded','site.link_down','device.offline','device.posture_blocked','kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable','ipsec.tunnel_down','ipsec.connection_down','ipsec.status_unavailable','agent.mcp_approval_pending'));
ALTER TABLE alert_deliveries DROP CONSTRAINT alert_deliveries_event_key_check;
ALTER TABLE alert_deliveries ADD CONSTRAINT alert_deliveries_event_key_check CHECK (event_key IN ('agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift','gateway.offline','gateway.policy_degraded','site.link_down','device.offline','device.posture_blocked','kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable','ipsec.tunnel_down','ipsec.connection_down','ipsec.status_unavailable','agent.mcp_approval_pending'));
ALTER TABLE alert_delivery_cooldowns DROP CONSTRAINT alert_delivery_cooldowns_event_key_check;
ALTER TABLE alert_delivery_cooldowns ADD CONSTRAINT alert_delivery_cooldowns_event_key_check CHECK (event_key IN ('agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift','gateway.offline','gateway.policy_degraded','site.link_down','device.offline','device.posture_blocked','kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable','ipsec.tunnel_down','ipsec.connection_down','ipsec.status_unavailable','agent.mcp_approval_pending'));
ALTER TABLE alert_occurrences DROP CONSTRAINT alert_occurrences_event_key_check;
ALTER TABLE alert_occurrences ADD CONSTRAINT alert_occurrences_event_key_check CHECK (event_key IN ('agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift','gateway.offline','gateway.policy_degraded','site.link_down','device.offline','device.posture_blocked','kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable','ipsec.tunnel_down','ipsec.connection_down','ipsec.status_unavailable','agent.mcp_approval_pending'));
DROP TABLE ai_internal_cas;
DROP TRIGGER ai_internal_endpoint_same_org ON ai_internal_endpoints;
DROP FUNCTION ai_internal_endpoint_same_org();
DROP TABLE ai_internal_endpoints;
DROP TABLE ai_workload_static_keys;
ALTER TABLE organizations DROP COLUMN ai_public_static_keys_allowed;
