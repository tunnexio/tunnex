-- S11 WF-S11-6, ruling (i): give the cert-expiry check something to read on deployments that already exist.
--
-- WHY THIS IS NEEDED AT ALL — the dormant-machinery trap, in its purest form. 0054 added cert_not_after as
-- NULLABLE, correctly: a new column must not retroactively declare every enrolled gateway bricked. But trace
-- who that leaves out. A RUNNING agent renews within 24h and stamps a real value. An ALREADY-DORMANT agent
-- never renews, so it stays NULL forever — and dormant agents are precisely the ones that go bricked. Without
-- this backfill, cert_expired_cannot_reconnect is unfirable for exactly the population it was built to name, on
-- every deployment in existence.
--
-- THE VALUE WRITTEN HERE IS A BOUND, NOT A MEASUREMENT. Read it that way. We do not store certificate issuance
-- time, so the true expiry (issuance + CertTTL) is not recoverable. What IS known: the certificate was
-- necessarily valid at the moment of the agent's last report, so issuance <= last_seen_at, and therefore
--
--     true_expiry = issuance + 48h  <=  last_seen_at + 48h  =  this bound
--
-- The bound is therefore an UPPER bound on the real expiry. That direction is the whole argument for doing this:
-- if the bound is already in the past, the real expiry is *even further* in the past, so the kind can NEVER
-- false-positive. It can be up to 48h LATE — reporting a gateway as still-fine when it has just bricked — which
-- is the safe direction to be wrong in. A guard that cannot cry wolf is worth more than a column that cannot
-- speak.
--
-- A future reader must not mistake a backfilled bound for an observed expiry. Any subsequent enroll or renew
-- OVERWRITES it unconditionally with the real NotAfter the CA minted (CreateNode / RenewNodeCert both set the
-- column), so a bound is self-correcting the moment an agent successfully talks to us again.
UPDATE nodes
   SET cert_not_after = last_seen_at + interval '48 hours'   -- agentca.CertTTL
 WHERE cert_not_after IS NULL
   -- A gateway that has NEVER reported has no basis for any bound, and inventing one would be the exact
   -- false-positive this ruling exists to avoid. It stays NULL = honestly unknown.
   AND last_seen_at IS NOT NULL;

COMMENT ON COLUMN nodes.cert_not_after IS
  'Expiry of the currently-issued agent cert. Stamped at enroll/renew from the certificate''s own NotAfter. Rows predating migration 0054 carry a BOUND backfilled by 0055 as last_seen_at + CertTTL (an UPPER bound on the true expiry, so it can never false-positive; overwritten by the real value on the next enroll/renew). NULL = never reported, honestly unknown. Past = the agent CANNOT reconnect (S11 WF-S11-6).';
