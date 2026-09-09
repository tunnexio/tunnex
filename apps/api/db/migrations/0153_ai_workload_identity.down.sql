-- Refuse rollback while identities or owned jobs exist. Archive/export them
-- through a separately approved migration; never silently delete authority.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM ai_workloads) THEN
        RAISE EXCEPTION 'workload identities exist; destructive rollback requires an explicit migration';
    END IF;
END $$;
DROP INDEX ai_video_workload_idempotency;
ALTER TABLE ai_video_jobs DROP CONSTRAINT ai_video_owner;
ALTER TABLE ai_video_jobs DROP COLUMN workload_id;
ALTER TABLE ai_video_jobs ADD CONSTRAINT ai_video_owner CHECK ((device_id IS NULL) <> (user_id IS NULL));
DROP TABLE ai_workload_tokens, ai_workload_assertions, ai_workload_instances, ai_workload_enrollment_keys, ai_workload_models, ai_workloads;
