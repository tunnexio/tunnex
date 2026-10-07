-- Explicitly export/remove saved review data before rollback; never silently lose it.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM beam_projects) OR EXISTS(SELECT 1 FROM beam_feedback) THEN
  RAISE EXCEPTION 'Export and remove Beam review rooms and feedback before downgrade';
 END IF;
END $$;
DROP TABLE beam_feedback;
ALTER TABLE beam_shares DROP CONSTRAINT beam_share_project_owner_fk;
ALTER TABLE beam_shares DROP COLUMN project_id;
DROP TABLE beam_projects;
