DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM ai_provider_connections WHERE provider='azure_foundry') THEN
 RAISE EXCEPTION 'Refusing Foundry rollback with retained connections or tombstones';
 END IF;
END $$;
ALTER TABLE ai_provider_connections DROP CONSTRAINT ai_provider_connections_provider_check;
ALTER TABLE ai_provider_connections ADD CONSTRAINT ai_provider_connections_provider_check CHECK(provider IN ('openrouter','openai','anthropic','gemini','groq','mistral','cerebras','xai','deepseek','custom','sagemaker'));
ALTER TABLE ai_provider_connections DROP CONSTRAINT ai_provider_connections_endpoint_check;
ALTER TABLE ai_provider_connections ADD CONSTRAINT ai_provider_connections_endpoint_check CHECK ((provider IN ('custom','sagemaker') AND endpoint_url IS NOT NULL AND char_length(endpoint_url) BETWEEN 1 AND 2048) OR (provider NOT IN ('custom','sagemaker') AND endpoint_url IS NULL));
