DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM ai_video_jobs WHERE expires_at>now()) THEN
  RAISE EXCEPTION 'cannot remove video job ownership while retained jobs exist';
 END IF;
END $$;
DROP TABLE ai_video_jobs;
