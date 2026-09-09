DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM ai_provider_connections, jsonb_each_text(model_modes) AS m WHERE m.value <> 'chat') THEN
  RAISE EXCEPTION 'Refusing mode rollback with retained non-chat models or tombstones';
 END IF;
END $$;
ALTER TABLE ai_provider_connections DROP CONSTRAINT ai_provider_model_modes_check;
ALTER TABLE ai_provider_connections DROP COLUMN model_modes;
DROP FUNCTION ai_provider_model_modes_valid(text[],jsonb);
