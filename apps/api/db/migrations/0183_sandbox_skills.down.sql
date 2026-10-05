DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM sandbox_skill_revisions) OR EXISTS(SELECT 1 FROM sandboxes WHERE selected_skills<>'[]') THEN RAISE EXCEPTION 'sandbox skills must be cleaned before downgrade'; END IF;
END $$;
DROP TRIGGER sandbox_skills_immutable ON sandboxes;
DROP FUNCTION sandbox_skills_immutable();
ALTER TABLE sandboxes DROP COLUMN selected_skills;
DROP TABLE sandbox_template_skills;
DROP TABLE sandbox_skill_revisions;
