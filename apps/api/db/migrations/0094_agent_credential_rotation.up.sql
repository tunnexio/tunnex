-- F05.1: one recoverable runtime-bearer rotation at a time. Existing
-- credentials remain revision 1/current; the control plane stores hashes only.
DROP INDEX agent_runtime_credentials_device_key;

ALTER TABLE agent_runtime_credentials
  ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  ADD COLUMN state text NOT NULL DEFAULT 'current'
    CHECK (state IN ('current', 'candidate', 'superseded', 'revoked')),
  ADD COLUMN candidate_expires_at timestamptz,
  ADD COLUMN activated_at timestamptz,
  ADD COLUMN terminal_at timestamptz,
  ADD COLUMN rotation_requested_at timestamptz,
  ADD COLUMN rotation_deadline timestamptz,
  ADD COLUMN rotation_requested_by uuid REFERENCES users (id) ON DELETE SET NULL,
  ADD CONSTRAINT agent_runtime_credentials_candidate_expiry_ck CHECK (
    (state = 'candidate' AND candidate_expires_at IS NOT NULL)
    OR (state <> 'candidate' AND candidate_expires_at IS NULL)
  ),
  ADD CONSTRAINT agent_runtime_credentials_request_ck CHECK (
    (rotation_requested_at IS NULL AND rotation_deadline IS NULL AND rotation_requested_by IS NULL)
    OR (rotation_requested_at IS NOT NULL AND rotation_deadline IS NOT NULL AND rotation_requested_by IS NOT NULL)
  );

-- Migration 0090's insert/update trigger intentionally rejects credential
-- writes for a non-active agent. Historical credentials can legitimately
-- belong to an agent suspended after bootstrap, so this one-time metadata
-- backfill must not reinterpret their lifecycle or fail the whole upgrade.
-- ALTER TABLE takes the required lock; the trigger is re-enabled in the same
-- migration transaction before normal writers can continue.
ALTER TABLE agent_runtime_credentials
  DISABLE TRIGGER agent_runtime_credentials_agent_only;
UPDATE agent_runtime_credentials SET activated_at = created_at;
ALTER TABLE agent_runtime_credentials
  ENABLE TRIGGER agent_runtime_credentials_agent_only;

CREATE UNIQUE INDEX agent_runtime_credentials_device_revision_key
  ON agent_runtime_credentials (device_id, revision);
CREATE UNIQUE INDEX agent_runtime_credentials_one_current_key
  ON agent_runtime_credentials (device_id) WHERE state = 'current';
CREATE UNIQUE INDEX agent_runtime_credentials_one_candidate_key
  ON agent_runtime_credentials (device_id) WHERE state = 'candidate';

-- Keep only the ten newest terminal credential rows per agent. This is the
-- complete bounded history for F05.1, not a generic history subsystem.
CREATE FUNCTION f05_bound_runtime_credential_history() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.state IN ('superseded', 'revoked') THEN
    DELETE FROM agent_runtime_credentials doomed
    USING (
      SELECT id FROM (
        SELECT id, row_number() OVER (
          PARTITION BY device_id ORDER BY terminal_at DESC NULLS LAST, created_at DESC, id DESC
        ) AS position
        FROM agent_runtime_credentials
        WHERE device_id = NEW.device_id AND state IN ('superseded', 'revoked')
      ) ranked WHERE position > 10
    ) retired_ids
    WHERE doomed.id = retired_ids.id;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER agent_runtime_credentials_f05_bounded_history
AFTER INSERT OR UPDATE OF state ON agent_runtime_credentials
FOR EACH ROW EXECUTE FUNCTION f05_bound_runtime_credential_history();

-- Every lifecycle writer gets the same cancellation semantics. Suspension
-- preserves the proven current bearer for resume but cancels pending work;
-- revoke/delete invalidates current and candidate credentials atomically with
-- the device transition.
CREATE FUNCTION f05_runtime_credential_lifecycle() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status = 'revoked' OR NEW.deleted_at IS NOT NULL THEN
    UPDATE agent_runtime_credentials
    SET state = 'revoked', revoked_at = COALESCE(revoked_at, now()),
        terminal_at = COALESCE(terminal_at, now()), candidate_expires_at = NULL,
        rotation_requested_at = NULL, rotation_deadline = NULL,
        rotation_requested_by = NULL
    WHERE device_id = NEW.id AND state IN ('current', 'candidate');
  ELSIF NEW.status <> 'active' THEN
    UPDATE agent_runtime_credentials
    SET state = 'revoked', revoked_at = COALESCE(revoked_at, now()),
        terminal_at = COALESCE(terminal_at, now()), candidate_expires_at = NULL
    WHERE device_id = NEW.id AND state = 'candidate';
    UPDATE agent_runtime_credentials
    SET rotation_requested_at = NULL, rotation_deadline = NULL,
        rotation_requested_by = NULL
    WHERE device_id = NEW.id AND state = 'current';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER devices_f05_runtime_credential_lifecycle
AFTER UPDATE OF status, deleted_at ON devices
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at)
EXECUTE FUNCTION f05_runtime_credential_lifecycle();

-- F05.2: one locally-generated WireGuard successor. The canonical current key
-- remains devices.public_key until the assigned gateway reports a real
-- candidate handshake. A prepared/staged candidate is public material only.
CREATE TABLE agent_wireguard_rotations (
  device_id uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
  org_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  current_revision bigint NOT NULL DEFAULT 1 CHECK (current_revision > 0),
  requested_revision bigint,
  state text NOT NULL DEFAULT 'current'
    CHECK (state IN ('current', 'requested', 'prepared', 'staged')),
  candidate_public_key text,
  requested_at timestamptz,
  deadline timestamptz,
  requested_by uuid REFERENCES users (id) ON DELETE SET NULL,
  staged_at timestamptz,
  completed_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agent_wireguard_rotations_shape_ck CHECK (
    (state = 'current' AND requested_revision IS NULL AND candidate_public_key IS NULL
      AND requested_at IS NULL AND deadline IS NULL AND requested_by IS NULL
      AND staged_at IS NULL)
    OR
    (state = 'requested' AND requested_revision = current_revision + 1
      AND candidate_public_key IS NULL AND requested_at IS NOT NULL
      AND deadline IS NOT NULL AND requested_by IS NOT NULL
      AND staged_at IS NULL)
    OR
    (state = 'prepared' AND requested_revision = current_revision + 1
      AND candidate_public_key ~ '^[A-Za-z0-9+/]{43}=$'
      AND requested_at IS NOT NULL AND deadline IS NOT NULL
      AND requested_by IS NOT NULL AND staged_at IS NULL)
    OR
    (state = 'staged' AND requested_revision = current_revision + 1
      AND candidate_public_key ~ '^[A-Za-z0-9+/]{43}=$'
      AND requested_at IS NOT NULL AND deadline IS NOT NULL
      AND requested_by IS NOT NULL AND staged_at IS NOT NULL)
  )
);

CREATE UNIQUE INDEX agent_wireguard_rotations_one_candidate_key
  ON agent_wireguard_rotations (candidate_public_key)
  WHERE candidate_public_key IS NOT NULL;

CREATE FUNCTION f05_wireguard_rotation_lifecycle() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status <> 'active' OR NEW.deleted_at IS NOT NULL THEN
    UPDATE agent_wireguard_rotations
    SET state = 'current', requested_revision = NULL,
        candidate_public_key = NULL, requested_at = NULL, deadline = NULL,
        requested_by = NULL, staged_at = NULL,
        updated_at = now()
    WHERE device_id = NEW.id AND state <> 'current';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER devices_f05_wireguard_rotation_lifecycle
AFTER UPDATE OF status, deleted_at ON devices
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at)
EXECUTE FUNCTION f05_wireguard_rotation_lifecycle();
