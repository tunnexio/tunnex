DO $$
BEGIN
  -- A rollback may remove only the expand-only legacy shape. Once a rotation
  -- request or successor exists, refuse before dropping any row or hash.
  IF EXISTS (
    SELECT 1 FROM agent_runtime_credentials
    WHERE revision <> 1 OR state <> 'current'
       OR candidate_expires_at IS NOT NULL OR terminal_at IS NOT NULL
       OR rotation_requested_at IS NOT NULL OR rotation_deadline IS NOT NULL
       OR rotation_requested_by IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'refusing to roll back 0094 while runtime credential rotation state exists';
  END IF;
  IF EXISTS (SELECT 1 FROM agent_wireguard_rotations) THEN
    RAISE EXCEPTION 'refusing to roll back 0094 while WireGuard rotation state exists';
  END IF;

  DROP TRIGGER devices_f05_wireguard_rotation_lifecycle ON devices;
  DROP FUNCTION f05_wireguard_rotation_lifecycle();
  DROP TABLE agent_wireguard_rotations;
  DROP TRIGGER devices_f05_runtime_credential_lifecycle ON devices;
  DROP FUNCTION f05_runtime_credential_lifecycle();
  DROP TRIGGER agent_runtime_credentials_f05_bounded_history ON agent_runtime_credentials;
  DROP FUNCTION f05_bound_runtime_credential_history();
  DROP INDEX agent_runtime_credentials_one_candidate_key;
  DROP INDEX agent_runtime_credentials_one_current_key;
  DROP INDEX agent_runtime_credentials_device_revision_key;
  ALTER TABLE agent_runtime_credentials
    DROP CONSTRAINT agent_runtime_credentials_request_ck,
    DROP CONSTRAINT agent_runtime_credentials_candidate_expiry_ck,
    DROP COLUMN rotation_requested_by,
    DROP COLUMN rotation_deadline,
    DROP COLUMN rotation_requested_at,
    DROP COLUMN terminal_at,
    DROP COLUMN activated_at,
    DROP COLUMN candidate_expires_at,
    DROP COLUMN state,
    DROP COLUMN revision;
  CREATE UNIQUE INDEX agent_runtime_credentials_device_key
    ON agent_runtime_credentials (device_id);
END $$;
