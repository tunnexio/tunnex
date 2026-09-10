DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM ai_provider_connections WHERE provider IN ('groq','mistral','cerebras','xai','deepseek')) OR
 EXISTS(SELECT 1 FROM ai_gateway_team_policies,unnest(models) AS model WHERE split_part(model,'/',1) IN ('groq','mistral','cerebras','xai','deepseek')) THEN
  RAISE EXCEPTION 'Refusing provider inventory rollback with retained added-provider connections or policies; follow documented rollback';
 END IF;
END $$;
ALTER TABLE ai_provider_connections DROP CONSTRAINT ai_provider_connections_provider_check;
ALTER TABLE ai_provider_connections ADD CONSTRAINT ai_provider_connections_provider_check CHECK(provider IN ('openrouter','openai','anthropic','gemini','custom'));
