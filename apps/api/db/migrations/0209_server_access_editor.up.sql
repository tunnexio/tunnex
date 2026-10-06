ALTER TABLE server_access_gateway_runtime ADD COLUMN editor_protocol_version integer NOT NULL DEFAULT 0 CHECK(editor_protocol_version IN (0,1));
ALTER TABLE server_access_servers ADD COLUMN developer_access_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE server_access_servers ADD CONSTRAINT server_access_developer_linux CHECK (NOT developer_access_enabled OR os='linux');
ALTER TABLE server_access_sessions DROP CONSTRAINT server_access_sessions_kind_check;
ALTER TABLE server_access_sessions ADD CONSTRAINT server_access_sessions_kind_check CHECK(kind IN ('terminal','check','editor'));
ALTER TABLE server_access_sessions ADD CONSTRAINT server_access_editor_unrecorded CHECK(kind<>'editor' OR NOT recording_enabled);
CREATE TABLE server_access_editor_connections (
 org_id uuid NOT NULL,
 session_id uuid PRIMARY KEY,
 code_hash bytea NOT NULL UNIQUE CHECK(octet_length(code_hash)=32),
 challenge text NOT NULL CHECK(length(challenge)=43),
 client_public_key text NOT NULL,
 host_private_sealed bytea NOT NULL,
 host_public_key text NOT NULL,
 token_hash bytea CHECK(octet_length(token_hash)=32),
 exchanged_at timestamptz,
 FOREIGN KEY(org_id,session_id) REFERENCES server_access_sessions(org_id,id) ON DELETE CASCADE
);
