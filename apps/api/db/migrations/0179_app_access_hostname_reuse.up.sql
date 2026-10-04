-- Acquire the tenant root before child DDL, matching application mutation order.
LOCK TABLE organizations IN EXCLUSIVE MODE;

-- A hostname belongs to exactly one live application. Retired claim tuples stay
-- present so immutable revisions, publications and audit UUIDs keep their history.
ALTER TABLE app_access_hostnames ADD COLUMN released_at timestamptz;
ALTER TABLE app_access_hostnames DROP CONSTRAINT app_access_hostnames_pkey;
CREATE UNIQUE INDEX app_access_hostname_live_claim ON app_access_hostnames(hostname) WHERE released_at IS NULL;

-- Disabled publications are retained history, never serving routes. The separate
-- live claim still reserves their hostname until confirmed archival.
ALTER TABLE app_access_serving_publications DROP CONSTRAINT app_access_serving_publications_hostname_key;
CREATE UNIQUE INDEX app_access_publication_live_hostname ON app_access_serving_publications(hostname) WHERE state IN ('pending','active');

CREATE FUNCTION app_access_hostname_history_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF ROW(NEW.hostname,NEW.org_id,NEW.app_id) IS DISTINCT FROM ROW(OLD.hostname,OLD.org_id,OLD.app_id)
    OR (OLD.released_at IS NOT NULL AND NEW.released_at IS DISTINCT FROM OLD.released_at) THEN
  RAISE EXCEPTION 'App Access hostname history is immutable' USING ERRCODE='23514';
 END IF;
 IF OLD.released_at IS NULL AND NEW.released_at IS NOT NULL AND NOT EXISTS(
  SELECT 1 FROM app_access_applications a
  JOIN app_access_serving_publications p ON p.org_id=a.org_id AND p.app_id=a.id
  WHERE a.org_id=NEW.org_id AND a.id=NEW.app_id AND a.state='archived'
   AND p.state='disabled' AND p.withdrawal_confirmed_at IS NOT NULL
   AND p.withdrawal_confirmed_authority_version=p.authority_version AND p.withdrawal_confirmed_generation=p.generation
   AND NOT EXISTS(SELECT 1 FROM app_access_publication_operations op WHERE op.org_id=a.org_id AND op.app_id=a.id AND op.status IN ('queued','checking'))
 ) THEN RAISE EXCEPTION 'App Access hostname release requires confirmed archival' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER app_access_hostname_history_guard BEFORE UPDATE ON app_access_hostnames FOR EACH ROW EXECUTE FUNCTION app_access_hostname_history_guard();

CREATE FUNCTION app_access_archive_release_hostnames() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF OLD.state='archived' AND NEW.state<>'archived' THEN
  RAISE EXCEPTION 'Archived App Access applications cannot be reactivated' USING ERRCODE='23514';
 END IF;
 IF OLD.state<>'archived' AND NEW.state='archived' THEN
  -- The application UPDATE owns the row lock; lifecycle operations already lock
  -- that same app before publication changes. Failure rolls back state and audit.
  IF NOT EXISTS(SELECT 1 FROM app_access_serving_publications p WHERE p.org_id=NEW.org_id AND p.app_id=NEW.id
    AND p.state='disabled' AND p.withdrawal_confirmed_at IS NOT NULL
    AND p.withdrawal_confirmed_authority_version=p.authority_version AND p.withdrawal_confirmed_generation=p.generation)
   OR EXISTS(SELECT 1 FROM app_access_publication_operations op WHERE op.org_id=NEW.org_id AND op.app_id=NEW.id AND op.status IN ('queued','checking')) THEN
   RAISE EXCEPTION 'App Access archive requires confirmed withdrawal' USING ERRCODE='23514';
  END IF;
  UPDATE app_access_hostnames SET released_at=now() WHERE org_id=NEW.org_id AND app_id=NEW.id AND released_at IS NULL;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER app_access_archive_release_hostnames AFTER UPDATE OF state ON app_access_applications FOR EACH ROW EXECUTE FUNCTION app_access_archive_release_hostnames();

-- Existing archives from the prior release are reusable only when their durable
-- withdrawal evidence is unambiguous; questionable reservations remain reserved.
UPDATE app_access_hostnames h SET released_at=now()
FROM app_access_applications a JOIN app_access_serving_publications p ON p.org_id=a.org_id AND p.app_id=a.id
WHERE h.org_id=a.org_id AND h.app_id=a.id AND a.state='archived' AND h.released_at IS NULL
 AND p.state='disabled' AND p.withdrawal_confirmed_at IS NOT NULL
 AND p.withdrawal_confirmed_authority_version=p.authority_version AND p.withdrawal_confirmed_generation=p.generation
 AND NOT EXISTS(SELECT 1 FROM app_access_publication_operations op WHERE op.org_id=a.org_id AND op.app_id=a.id AND op.status IN ('queued','checking'));
