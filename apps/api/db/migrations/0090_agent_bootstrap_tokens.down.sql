DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM agent_runtime_credentials LIMIT 1)
       OR EXISTS (SELECT 1 FROM agent_bootstrap_tokens LIMIT 1) THEN
        RAISE EXCEPTION 'refusing to roll back 0090 while bootstrap credentials exist';
    END IF;
    DROP TRIGGER IF EXISTS agent_runtime_credentials_agent_only ON agent_runtime_credentials;
    DROP FUNCTION IF EXISTS f03_runtime_credential_agent_only();
    DROP TABLE IF EXISTS agent_runtime_credentials;
    DROP TABLE IF EXISTS agent_bootstrap_tokens;
    ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_org_id_id_f03_key;
    ALTER TABLE nodes DROP CONSTRAINT IF EXISTS nodes_org_id_id_f03_key;
END $$;
