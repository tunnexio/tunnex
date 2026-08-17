-- F02: an AI agent is an independently identified WireGuard peer homed on a
-- gateway. Gateway affinity is routing placement, not identity: more than one
-- agent may use the same gateway while each keeps its own device id, public key,
-- and org-scoped tunnel address.
--
-- 0067 made (node_id) unique for live agent rows to stop re-enrolment leaks. The
-- device-create transaction now already serializes all org allocations and the
-- existing public-key/IP indexes remain the structural duplicate backstops. Drop
-- only the obsolete cardinality index; do not weaken either identity invariant.
DROP INDEX IF EXISTS devices_agent_node_key;
