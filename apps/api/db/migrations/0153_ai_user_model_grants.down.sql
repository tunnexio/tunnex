DO $$ BEGIN IF EXISTS(SELECT 1 FROM ai_video_jobs WHERE user_id IS NOT NULL) THEN RAISE EXCEPTION 'Retained human video jobs prevent downgrade'; END IF; END $$;
DROP INDEX ai_video_user_idempotency;
ALTER TABLE ai_video_jobs DROP CONSTRAINT ai_video_owner;
ALTER TABLE ai_video_jobs DROP COLUMN user_id;
ALTER TABLE ai_video_jobs ALTER COLUMN device_id SET NOT NULL;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM ai_user_model_grants) THEN
        RAISE EXCEPTION 'retain AI user grant accounting before downgrade';
    END IF;
END $$;
DROP TABLE ai_user_model_grants;
