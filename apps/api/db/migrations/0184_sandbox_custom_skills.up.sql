CREATE TABLE sandbox_custom_skills (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL REFERENCES organizations(id),
 owner_id uuid NOT NULL REFERENCES users(id),
 current_revision_id uuid NOT NULL,
 generation bigint NOT NULL DEFAULT 1 CHECK(generation BETWEEN 1 AND 20),
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
 created_at timestamptz NOT NULL DEFAULT now(),
 deleted_at timestamptz,
 UNIQUE(org_id,id,owner_id),
 UNIQUE(org_id,owner_id,idempotency_key)
);
ALTER TABLE sandbox_skill_revisions
 ADD COLUMN owner_id uuid REFERENCES users(id),
 ADD COLUMN custom_skill_id uuid,
 ADD COLUMN revision integer NOT NULL DEFAULT 1 CHECK(revision BETWEEN 1 AND 20),
 ADD COLUMN document text,
 ADD CONSTRAINT sandbox_custom_revision_shape CHECK(
  (owner_id IS NULL AND custom_skill_id IS NULL AND document IS NULL) OR
  (owner_id IS NOT NULL AND custom_skill_id IS NOT NULL AND document IS NOT NULL AND octet_length(document) BETWEEN 1 AND 32768)),
 ADD CONSTRAINT sandbox_custom_revision_identity UNIQUE(org_id,id,owner_id,custom_skill_id),
 ADD CONSTRAINT sandbox_custom_revision_version UNIQUE(custom_skill_id,revision),
 ADD CONSTRAINT sandbox_custom_revision_owner FOREIGN KEY(org_id,custom_skill_id,owner_id) REFERENCES sandbox_custom_skills(org_id,id,owner_id);
ALTER TABLE sandbox_custom_skills ADD CONSTRAINT sandbox_custom_current_revision FOREIGN KEY(org_id,current_revision_id,owner_id,id)
 REFERENCES sandbox_skill_revisions(org_id,id,owner_id,custom_skill_id) DEFERRABLE INITIALLY DEFERRED;
CREATE FUNCTION sandbox_custom_skill_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.id,NEW.org_id,NEW.owner_id,NEW.idempotency_key,NEW.request_hash,NEW.created_at)
 IS DISTINCT FROM (OLD.id,OLD.org_id,OLD.owner_id,OLD.idempotency_key,OLD.request_hash,OLD.created_at) THEN
  RAISE EXCEPTION 'custom skill ownership/create identity is immutable';
 END IF;
 IF OLD.deleted_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'deleted custom skill cannot change'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sandbox_custom_skill_identity BEFORE UPDATE ON sandbox_custom_skills FOR EACH ROW EXECUTE FUNCTION sandbox_custom_skill_identity();
