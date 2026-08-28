DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM fqdn_resolver_context_configs)
       OR EXISTS (SELECT 1 FROM fqdn_resource_answer_generations WHERE resolver_config_id IS NOT NULL) THEN
        RAISE EXCEPTION 'refusing to roll back 0115: resolver configuration or generation snapshot history exists';
    END IF;
END;
$$;

DROP INDEX IF EXISTS fqdn_resource_answer_generations_config_idx;
ALTER TABLE fqdn_resource_answer_generations DROP CONSTRAINT IF EXISTS fqdn_generation_resolver_config_fk;
ALTER TABLE fqdn_resource_answer_generations DROP COLUMN IF EXISTS resolver_config_id;
DROP TRIGGER IF EXISTS fqdn_resolver_config_context_before_write ON fqdn_resolver_context_configs;
DROP FUNCTION IF EXISTS fqdn_resolver_config_context_is_selected();
DROP TRIGGER IF EXISTS fqdn_resolver_config_before_activate ON fqdn_resolver_context_configs;
DROP FUNCTION IF EXISTS fqdn_resolver_config_require_endpoint();
DROP TABLE IF EXISTS fqdn_resolver_context_endpoints;
DROP TABLE IF EXISTS fqdn_resolver_context_configs;
