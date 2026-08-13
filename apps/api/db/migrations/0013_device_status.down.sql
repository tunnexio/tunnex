ALTER TABLE devices ADD COLUMN last_handshake_at timestamptz;
DROP TABLE IF EXISTS device_status;
