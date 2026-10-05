CREATE TABLE sandbox_skill_revisions (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL REFERENCES organizations(id),
 manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object' AND octet_length(manifest::text)<=65536),
 enabled boolean NOT NULL DEFAULT false,
 UNIQUE(org_id,id)
);
CREATE TRIGGER sandbox_skill_immutable BEFORE UPDATE ON sandbox_skill_revisions FOR EACH ROW EXECUTE FUNCTION sandbox_template_immutable();
CREATE TABLE sandbox_template_skills (
 org_id uuid NOT NULL,
 template_id uuid NOT NULL,
 revision_id uuid NOT NULL,
 PRIMARY KEY(template_id,revision_id),
 FOREIGN KEY(org_id,template_id) REFERENCES sandbox_templates(org_id,id),
 FOREIGN KEY(org_id,revision_id) REFERENCES sandbox_skill_revisions(org_id,id)
);
ALTER TABLE sandboxes ADD COLUMN selected_skills jsonb NOT NULL DEFAULT '[]' CHECK(jsonb_typeof(selected_skills)='array' AND jsonb_array_length(selected_skills)<=16);
CREATE FUNCTION sandbox_skills_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.selected_skills IS DISTINCT FROM OLD.selected_skills THEN RAISE EXCEPTION 'sandbox selected skills are immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sandbox_skills_immutable BEFORE UPDATE OF selected_skills ON sandboxes FOR EACH ROW EXECUTE FUNCTION sandbox_skills_immutable();
