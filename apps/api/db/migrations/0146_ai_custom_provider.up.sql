ALTER TABLE ai_provider_connections DROP CONSTRAINT ai_provider_connections_provider_check;
ALTER TABLE ai_provider_connections ADD CONSTRAINT ai_provider_connections_provider_check CHECK(provider IN ('openrouter','openai','anthropic','gemini','custom'));
ALTER TABLE ai_provider_connections ADD COLUMN endpoint_url text;
ALTER TABLE ai_provider_connections ADD CONSTRAINT ai_provider_connections_endpoint_check CHECK ((provider='custom' AND endpoint_url IS NOT NULL AND char_length(endpoint_url) BETWEEN 1 AND 2048) OR (provider<>'custom' AND endpoint_url IS NULL));
