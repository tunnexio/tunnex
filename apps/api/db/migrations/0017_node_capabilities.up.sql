-- 0017 node capabilities (S3.7 gateway egress NAT).
-- A JSONB map of gateway capabilities the agent probes + reports (forward-compat for
-- future caps: ipv6 egress, on-gateway DNS, site-routing). First key: egress_nat —
-- whether the gateway can source-NAT full-tunnel client traffic to the internet. The
-- API refuses a full_tunnel device against a gateway whose egress_nat is false
-- (gateway_no_egress) rather than let it silently blackhole.
ALTER TABLE nodes ADD COLUMN capabilities jsonb NOT NULL DEFAULT '{}'::jsonb;
