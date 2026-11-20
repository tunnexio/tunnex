-- 0236 node-peer receive progress (SSI-12: fast hub failover).
--
-- The failover controller judged a hub dead from its WireGuard handshake AGE alone. A healthy link's
-- handshake age legitimately reaches ~200s between rekeys, so the stale window had to be 240s and a dead
-- primary cost five minutes of downtime.
--
-- Every site-link peer carries a persistent keepalive, so a LIVING peer's receive counter advances every
-- few seconds even on an idle link, and a dead peer's never does. The agent already reports the counter;
-- the control plane stored only its latest value and so could not tell "advancing" from "frozen". These
-- two columns are that memory:
--
--   rx_advanced_at   when the control plane last saw this row's rx_bytes CHANGE (control-plane clock)
--   stalled_reports  how many consecutive reports since then carried the same rx_bytes
--
-- Both are written by the same upsert as the gauge. NULL rx_advanced_at = a row written before this
-- migration that has not been re-reported yet: no receive evidence, the handshake rule still applies.
ALTER TABLE node_peer_status
    ADD COLUMN rx_advanced_at  timestamptz,
    ADD COLUMN stalled_reports integer NOT NULL DEFAULT 0;
