-- Saved projects are presets, never new authority for a historical share.
CREATE TABLE beam_projects (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(), org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 owner_id uuid NOT NULL REFERENCES users(id), name text NOT NULL CHECK(length(name) BETWEEN 1 AND 100),
 target jsonb NOT NULL, duration_seconds integer NOT NULL CHECK(duration_seconds BETWEEN 60 AND 86400),
 grants jsonb NOT NULL DEFAULT '[]', version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(org_id,id), UNIQUE(org_id,id,owner_id)
);
CREATE INDEX beam_projects_owner_idx ON beam_projects(org_id,owner_id,updated_at DESC,id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON beam_projects FOR EACH ROW EXECUTE FUNCTION set_updated_at();
ALTER TABLE beam_shares ADD COLUMN project_id uuid;
ALTER TABLE beam_shares ADD CONSTRAINT beam_share_project_owner_fk FOREIGN KEY(org_id,project_id,publisher_id) REFERENCES beam_projects(org_id,id,owner_id);
CREATE INDEX beam_shares_project_idx ON beam_shares(org_id,project_id,created_at DESC,id) WHERE project_id IS NOT NULL;
CREATE TABLE beam_feedback (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(), org_id uuid NOT NULL, share_id uuid NOT NULL,
 author_id uuid NOT NULL REFERENCES users(id), body text NOT NULL CHECK(length(body)<=4000),
 status text NOT NULL CHECK(status IN ('comment','approved','changes_requested')),
 screenshot bytea CHECK(octet_length(screenshot)<=262144), created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(org_id,share_id) REFERENCES beam_shares(org_id,id) ON DELETE CASCADE,
 CHECK(length(body)>0 OR status<>'comment' OR screenshot IS NOT NULL)
);
CREATE INDEX beam_feedback_share_idx ON beam_feedback(org_id,share_id,created_at DESC,id);
