CREATE TABLE app_access_settings (
 org_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
 enabled boolean NOT NULL DEFAULT false,
 version bigint NOT NULL DEFAULT 1 CHECK (version > 0)
);
CREATE TABLE app_access_applications (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
 draft_revision bigint NOT NULL DEFAULT 1 CHECK (draft_revision > 0),
 state text NOT NULL DEFAULT 'draft' CHECK (state = 'draft'),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE (org_id,id)
);
CREATE TABLE app_access_revisions (
 org_id uuid NOT NULL,
 app_id uuid NOT NULL,
 revision bigint NOT NULL CHECK (revision > 0),
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
 description text NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
 icon text NOT NULL DEFAULT '' CHECK (length(icon) <= 64),
 origin_url text NOT NULL CHECK (length(origin_url) BETWEEN 1 AND 2048),
 gateway_id uuid NOT NULL,
 public_hostname text NOT NULL CHECK (length(public_hostname) BETWEEN 1 AND 253),
 idle_timeout_seconds integer NOT NULL CHECK (idle_timeout_seconds BETWEEN 60 AND 1800),
 absolute_timeout_seconds integer NOT NULL CHECK (absolute_timeout_seconds BETWEEN 300 AND 28800 AND absolute_timeout_seconds >= idle_timeout_seconds),
 digest text NOT NULL CHECK (length(digest) = 64),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (org_id,app_id,revision),
 FOREIGN KEY (org_id,app_id) REFERENCES app_access_applications(org_id,id) ON DELETE CASCADE,
 FOREIGN KEY (org_id,gateway_id) REFERENCES nodes(org_id,id) ON DELETE RESTRICT
);
ALTER TABLE app_access_applications ADD CONSTRAINT app_access_draft_revision_fk FOREIGN KEY (org_id,id,draft_revision) REFERENCES app_access_revisions(org_id,app_id,revision) DEFERRABLE INITIALLY DEFERRED;
-- Historical host claims remain reserved, including after draft hostname edits.
CREATE TABLE app_access_hostnames (
 hostname text PRIMARY KEY CHECK (hostname = lower(hostname)),
 UNIQUE (hostname,org_id,app_id),
 org_id uuid NOT NULL,
 app_id uuid NOT NULL,
 FOREIGN KEY (org_id,app_id) REFERENCES app_access_applications(org_id,id) ON DELETE CASCADE
);
ALTER TABLE app_access_revisions ADD CONSTRAINT app_access_revision_host_fk FOREIGN KEY (public_hostname,org_id,app_id) REFERENCES app_access_hostnames(hostname,org_id,app_id) ON DELETE RESTRICT;
CREATE FUNCTION app_access_revision_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'App Access revisions are immutable' USING ERRCODE='23514'; END $$;
CREATE TRIGGER app_access_revision_immutable BEFORE UPDATE ON app_access_revisions FOR EACH ROW EXECUTE FUNCTION app_access_revision_immutable();
