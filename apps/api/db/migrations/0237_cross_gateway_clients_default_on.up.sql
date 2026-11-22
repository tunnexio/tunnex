-- K8L-7: a person connects once and reaches every network and cluster their access rules allow,
-- whichever gateway they connected through. That needs each gateway to know which gateway owns each
-- device address (the cross-gateway client graph, 0166). It was opt-in; without it a device on a
-- gateway that is not the hub silently cannot reach another network. It is now on unless an
-- administrator turns it off. Access rules are unchanged: in enforcing mode only granted flows pass.
ALTER TABLE organizations ALTER COLUMN cross_gateway_clients_enabled SET DEFAULT true;
UPDATE organizations SET cross_gateway_clients_enabled = true WHERE NOT cross_gateway_clients_enabled;
