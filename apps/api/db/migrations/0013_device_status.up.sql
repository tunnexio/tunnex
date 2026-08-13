-- 0013 device live status (S3.6).
--
-- Telemetry (last handshake, byte counters, current endpoint) lands in a LEAN
-- per-device table, not on the devices row: it is written on every agent report
-- (~30s), and churning the devices row — which carries the unique indexes — would
-- bloat them and drive vacuum. One row per device, upserted in a single batched
-- statement per report.
--
-- Byte counters are RAW gauges as read from WireGuard: they RESET when the
-- interface restarts. They are for display only — do NOT sum them as monotonic
-- (server-side accumulation is a metrics concern, S11.1).

CREATE TABLE device_status (
    device_id         uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    last_handshake_at timestamptz,               -- null until the first handshake
    rx_bytes          bigint NOT NULL DEFAULT 0,  -- raw gauge; resets on interface restart
    tx_bytes          bigint NOT NULL DEFAULT 0,  -- raw gauge; resets on interface restart
    updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON device_status
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- The placeholder column on devices (added in 0010, never populated) is
-- superseded by this table.
ALTER TABLE devices DROP COLUMN last_handshake_at;
