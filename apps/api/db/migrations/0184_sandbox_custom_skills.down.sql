DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM sandbox_custom_skills) THEN RAISE EXCEPTION 'custom skill content must be preserved/cleaned before downgrade'; END IF;
END $$;
ALTER TABLE sandbox_custom_skills DROP CONSTRAINT sandbox_custom_current_revision;
ALTER TABLE sandbox_skill_revisions DROP CONSTRAINT sandbox_custom_revision_owner,
 DROP CONSTRAINT sandbox_custom_revision_identity, DROP CONSTRAINT sandbox_custom_revision_version, DROP CONSTRAINT sandbox_custom_revision_shape,
 DROP COLUMN owner_id, DROP COLUMN custom_skill_id, DROP COLUMN revision, DROP COLUMN document;
DROP TABLE sandbox_custom_skills;
DROP FUNCTION sandbox_custom_skill_identity();
