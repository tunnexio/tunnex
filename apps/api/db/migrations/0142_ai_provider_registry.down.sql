DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM ai_provider_connections WHERE provider <> 'openrouter') OR
 EXISTS(SELECT 1 FROM ai_gateway_team_policies,unnest(models) AS model WHERE model NOT LIKE 'openrouter/%') THEN
  RAISE EXCEPTION 'Refusing provider registry rollback with retained non-OpenRouter connections or policies; follow documented rollback';
 END IF;
END $$;
ALTER TABLE ai_provider_connections DROP CONSTRAINT ai_provider_connections_provider_check;
ALTER TABLE ai_provider_connections ADD CONSTRAINT ai_provider_connections_provider_check CHECK(provider='openrouter');
