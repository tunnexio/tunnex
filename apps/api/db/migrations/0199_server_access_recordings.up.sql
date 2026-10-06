ALTER TABLE server_access_settings ADD COLUMN recording_retention_days integer NOT NULL DEFAULT 7 CHECK(recording_retention_days BETWEEN 1 AND 30), ADD COLUMN recording_max_session_bytes integer NOT NULL DEFAULT 4194304 CHECK(recording_max_session_bytes BETWEEN 65536 AND 16777216), ADD COLUMN recording_max_org_bytes integer NOT NULL DEFAULT 67108864 CHECK(recording_max_org_bytes BETWEEN 65536 AND 1073741824), ADD CHECK(recording_max_org_bytes>=recording_max_session_bytes);
-- Bounded encrypted recordings; terminal content never enters ordinary audit rows.
CREATE TABLE server_access_recordings (
 org_id uuid NOT NULL,
 session_id uuid NOT NULL,
 status text NOT NULL DEFAULT 'capturing' CHECK(status IN ('capturing','available','incomplete','failed','expired')),
 key_sealed bytea,
 max_payload_bytes integer NOT NULL DEFAULT 4194304 CHECK(max_payload_bytes BETWEEN 65536 AND 16777216),
 max_org_bytes integer NOT NULL DEFAULT 67108864,
 next_seq integer NOT NULL DEFAULT 0 CHECK(next_seq BETWEEN 0 AND 4096),
 payload_bytes integer NOT NULL DEFAULT 0 CHECK(payload_bytes>=0 AND payload_bytes<=max_payload_bytes),
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL DEFAULT now()+interval '7 days',
 PRIMARY KEY(org_id,session_id),
 FOREIGN KEY(org_id,session_id) REFERENCES server_access_sessions(org_id,id) ON DELETE CASCADE
);
CREATE TABLE server_access_recording_chunks (
 org_id uuid NOT NULL,
 session_id uuid NOT NULL,
 seq integer NOT NULL CHECK(seq>=0 AND seq<4096),
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext)<=32768),
 PRIMARY KEY(org_id,session_id,seq),
 FOREIGN KEY(org_id,session_id) REFERENCES server_access_recordings(org_id,session_id) ON DELETE CASCADE
);
CREATE INDEX server_access_recording_retention ON server_access_recordings(expires_at) WHERE status<>'expired';
