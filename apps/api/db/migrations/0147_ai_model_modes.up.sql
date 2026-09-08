CREATE FUNCTION ai_provider_model_modes_valid(models text[], modes jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
 SELECT jsonb_typeof(modes) = 'object' AND NOT EXISTS (
  SELECT 1 FROM jsonb_each_text(CASE WHEN jsonb_typeof(modes) = 'object' THEN modes ELSE '{}'::jsonb END) AS m
  WHERE NOT (m.key = ANY(models)) OR m.value IS NULL OR m.value NOT IN
   ('chat','completion','embedding','audio_speech','audio_transcription','image_generation','video_generation','rerank')
 )
$$;
ALTER TABLE ai_provider_connections ADD COLUMN model_modes jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE ai_provider_connections ADD CONSTRAINT ai_provider_model_modes_check CHECK(ai_provider_model_modes_valid(models,model_modes));
COMMENT ON COLUMN ai_provider_connections.model_modes IS 'Exact model protocol. Omitted entries retain backwards-compatible chat semantics; no secrets.';
