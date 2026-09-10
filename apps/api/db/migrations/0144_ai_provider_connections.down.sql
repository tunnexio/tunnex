DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM ai_provider_connections) THEN
  RAISE EXCEPTION 'Refusing to remove populated AI provider ownership; disable managed assignments and follow documented rollback';
 END IF;
END $$;
DROP TABLE ai_provider_connections;
DROP TABLE ai_provider_legacy_keys;
