CREATE TABLE app_access_proxy_credentials (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 100),
 token_hash bytea NOT NULL UNIQUE CHECK(octet_length(token_hash)=32),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 created_at timestamptz NOT NULL DEFAULT now(),
 revoked_at timestamptz
);
-- Empty until reviewed publication is implemented; drafts remain drafts.
CREATE TABLE app_access_serving_publications (
 org_id uuid NOT NULL,
 app_id uuid NOT NULL,
 gateway_id uuid NOT NULL,
 revision bigint NOT NULL,
 digest text NOT NULL CHECK(length(digest)=64),
 hostname text NOT NULL UNIQUE,
 generation uuid NOT NULL UNIQUE DEFAULT uuid_generate_v7(),
 purpose text NOT NULL DEFAULT 'browser_proxy' CHECK(purpose='browser_proxy'),
 authority_version bigint NOT NULL DEFAULT 1 CHECK(authority_version>0),
 state text NOT NULL CHECK(state IN('pending','active','disabled')),
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(org_id,app_id),
 FOREIGN KEY(org_id,app_id,gateway_id,revision,digest) REFERENCES app_access_revisions(org_id,app_id,gateway_id,revision,digest) ON DELETE RESTRICT,
 FOREIGN KEY(hostname,org_id,app_id) REFERENCES app_access_hostnames(hostname,org_id,app_id) ON DELETE RESTRICT
);
