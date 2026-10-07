-- Beam resources use an independent audience and never gateway/node authority.
CREATE TABLE beam_policies (
 org_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
 enabled boolean NOT NULL DEFAULT false, version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 publisher_group_ids uuid[] NOT NULL DEFAULT '{}', reviewer_user_ids uuid[] NOT NULL DEFAULT '{}', reviewer_group_ids uuid[] NOT NULL DEFAULT '{}',
 max_duration_seconds integer NOT NULL DEFAULT 86400 CHECK(max_duration_seconds BETWEEN 60 AND 86400),
 max_shares integer NOT NULL DEFAULT 5 CHECK(max_shares BETWEEN 1 AND 25), require_mfa boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON beam_policies FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TABLE beam_shares (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(), org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 publisher_id uuid NOT NULL REFERENCES users(id), source_credential_id uuid REFERENCES cli_credentials(id), source_session_id text NOT NULL DEFAULT '',
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 100), hostname text NOT NULL UNIQUE,
 target jsonb NOT NULL, digest text NOT NULL CHECK(length(digest)=64), idempotency_key uuid NOT NULL, request_digest text NOT NULL,
 state text NOT NULL DEFAULT 'starting' CHECK(state IN ('starting','active','paused','stopped','expired','revoked')),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0), authority_version bigint NOT NULL DEFAULT 1 CHECK(authority_version>0),
 connector_id uuid NOT NULL DEFAULT uuid_generate_v7(), generation uuid NOT NULL DEFAULT uuid_generate_v7(), certificate_serial text,
 serving_authority_version bigint NOT NULL DEFAULT 1 CHECK(serving_authority_version>0), last_channel_at timestamptz,
 origin_ready boolean NOT NULL DEFAULT false, last_heartbeat_at timestamptz, expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(org_id,publisher_id,idempotency_key), UNIQUE(org_id,id), CHECK(expires_at>created_at)
);
CREATE INDEX beam_shares_org_owner_idx ON beam_shares(org_id,publisher_id,created_at DESC);
CREATE INDEX beam_shares_expiry_idx ON beam_shares(expires_at) WHERE state IN ('starting','active','paused');
CREATE TRIGGER set_updated_at BEFORE UPDATE ON beam_shares FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TABLE beam_grants (
 org_id uuid NOT NULL, share_id uuid NOT NULL, subject_kind text NOT NULL CHECK(subject_kind IN ('user','group')), subject_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(share_id,subject_kind,subject_id),
 FOREIGN KEY(org_id,share_id) REFERENCES beam_shares(org_id,id) ON DELETE CASCADE
);
CREATE INDEX beam_grants_org_idx ON beam_grants(org_id,share_id);
CREATE TABLE beam_pending_launches (
 nonce_hash bytea PRIMARY KEY CHECK(octet_length(nonce_hash)=32), org_id uuid NOT NULL, share_id uuid NOT NULL,
 relative_target text NOT NULL, expires_at timestamptz NOT NULL,
 FOREIGN KEY(org_id,share_id) REFERENCES beam_shares(org_id,id) ON DELETE CASCADE
);
CREATE TABLE beam_launch_codes (
 code_hash bytea PRIMARY KEY CHECK(octet_length(code_hash)=32), org_id uuid NOT NULL, share_id uuid NOT NULL, user_id uuid NOT NULL REFERENCES users(id),
 parent_session_id text NOT NULL, nonce_hash bytea NOT NULL CHECK(octet_length(nonce_hash)=32), relative_target text NOT NULL,
 expires_at timestamptz NOT NULL, consumed_at timestamptz,
 FOREIGN KEY(org_id,share_id) REFERENCES beam_shares(org_id,id) ON DELETE CASCADE
);
CREATE TABLE beam_browser_sessions (
 token_hash bytea PRIMARY KEY CHECK(octet_length(token_hash)=32), org_id uuid NOT NULL, share_id uuid NOT NULL, user_id uuid NOT NULL REFERENCES users(id),
 parent_session_id text NOT NULL, expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(org_id,share_id) REFERENCES beam_shares(org_id,id) ON DELETE CASCADE
);
CREATE TABLE beam_streams (
 id uuid PRIMARY KEY, org_id uuid NOT NULL, share_id uuid NOT NULL, token_hash bytea NOT NULL REFERENCES beam_browser_sessions(token_hash) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(org_id,share_id) REFERENCES beam_shares(org_id,id) ON DELETE CASCADE
);
CREATE INDEX beam_streams_org_share_idx ON beam_streams(org_id,share_id,expires_at);
