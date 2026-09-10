DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM ai_provider_connections WHERE provider='custom') THEN
  RAISE EXCEPTION 'Refusing custom provider rollback with retained connections or tombstones; follow documented rollback';
 END IF;
END $$;
ALTER TABLE ai_provider_connections DROP CONSTRAINT ai_provider_connections_endpoint_check;
ALTER TABLE ai_provider_connections DROP COLUMN endpoint_url;
ALTER TABLE ai_provider_connections DROP CONSTRAINT ai_provider_connections_provider_check;
ALTER TABLE ai_provider_connections ADD CONSTRAINT ai_provider_connections_provider_check CHECK(provider IN ('openrouter','openai','anthropic','gemini'));
