-- Retire editor authority before removing its policy and credentials. Retain session audit history.
UPDATE server_access_sessions SET status='ended',reason='editor_feature_removed',ended_at=COALESCE(ended_at,now()) WHERE kind='editor';
DROP TABLE server_access_editor_connections;
ALTER TABLE server_access_sessions DROP CONSTRAINT server_access_editor_unrecorded;
ALTER TABLE server_access_sessions DROP CONSTRAINT server_access_sessions_kind_check;
-- Historical editor rows are retained; old application versions do not admit them.
ALTER TABLE server_access_sessions ADD CONSTRAINT server_access_sessions_kind_check CHECK(kind IN ('terminal','check','editor'));
ALTER TABLE server_access_servers DROP COLUMN developer_access_enabled;

ALTER TABLE server_access_gateway_runtime DROP COLUMN editor_protocol_version;
