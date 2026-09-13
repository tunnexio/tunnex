ALTER TABLE ai_provider_connections DROP CONSTRAINT ai_provider_connections_models_check;
ALTER TABLE ai_provider_connections ADD CONSTRAINT ai_provider_connections_models_check CHECK(cardinality(models) BETWEEN 0 AND 32);
