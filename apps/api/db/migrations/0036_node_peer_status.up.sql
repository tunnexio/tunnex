-- 0036 node-peer live status (S8.6 L1 / HA substrate).
--
-- device_status (0013) stores a reporting node's DEVICE peers, keyed by the device. A gateway's wg0 peers
-- ALSO include OTHER GATEWAYS (site-link peers, S8.2) whose pubkey is a NODE, not a device — so
-- UpsertDeviceStatus no-ops them (pubkey matches no device row). This table is that no-op's SIBLING: the
-- reporting node's GATEWAY-peer telemetry, keyed (node_id, public_key). It is the substrate D3's failover
-- staleness clock reads (per-hub per-spoke handshake freshness) AND the S8.5 L1 site-link card metrics.
-- REPORTED != STORED (the law) gets its fix: the CP finally stores the gateway-peer telemetry the agent
-- already sends.
--
-- GAUGE, not a time series: one row per (node_id, public_key) holds the LATEST observation. rx/tx are RAW
-- WireGuard gauges (reset on interface restart) — display only, never summed as monotonic (server-side
-- accumulation is S11.1's line, deliberately NOT here). Written on the existing ~30s agent report; no new
-- agent-side collection.
--
-- RETENTION: rows cascade with the REPORTING node (node_id FK ON DELETE CASCADE). A departed PEER's rows
-- (the peer gateway deleted, but a reporter still names its old pubkey) are unreferenced residue the read
-- path never surfaces — reads join the LIVE site-link graph, which excludes a dead gateway — so there is NO
-- sweep machinery (dormant-machinery law: don't build a sweep for rows the read already ignores).

CREATE TABLE node_peer_status (
    node_id           uuid NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,  -- the REPORTING gateway
    public_key        text NOT NULL,                                          -- the PEER gateway's WG pubkey
    last_handshake_at timestamptz,               -- null until the first handshake
    rx_bytes          bigint NOT NULL DEFAULT 0,  -- raw gauge; resets on interface restart
    tx_bytes          bigint NOT NULL DEFAULT 0,  -- raw gauge; resets on interface restart
    updated_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (node_id, public_key)
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON node_peer_status
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
