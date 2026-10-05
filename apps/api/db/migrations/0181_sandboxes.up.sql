-- First-class Sandboxes. No runtime is enabled by applying this migration.
ALTER TABLE organizations
 ADD COLUMN sandboxes_enabled boolean NOT NULL DEFAULT false,
 ADD COLUMN max_sandboxes_per_user integer NOT NULL DEFAULT 2 CHECK (max_sandboxes_per_user BETWEEN 1 AND 100),
 ADD COLUMN max_sandboxes integer NOT NULL DEFAULT 20 CHECK (max_sandboxes BETWEEN 1 AND 10000);
ALTER TABLE devices DROP CONSTRAINT devices_kind_check;
ALTER TABLE devices ADD CONSTRAINT devices_kind_check CHECK (kind IN ('human','agent','sandbox'));

CREATE TABLE sandbox_templates (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
 image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[a-f0-9]{64}$'),
 maximum_scope jsonb NOT NULL CHECK (jsonb_typeof(maximum_scope)='array' AND jsonb_array_length(maximum_scope)<=64),
 memory_mib integer NOT NULL CHECK (memory_mib BETWEEN 64 AND 4096),
 max_ttl_seconds integer NOT NULL CHECK (max_ttl_seconds BETWEEN 300 AND 86400),
 enabled boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(org_id,id)
);
CREATE TABLE sandboxes (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 creator_id uuid NOT NULL REFERENCES users(id),
 template_id uuid NOT NULL,
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
 requested_scope jsonb NOT NULL CHECK (jsonb_typeof(requested_scope)='array' AND jsonb_array_length(requested_scope)<=64),
 peer_id uuid UNIQUE,
 desired_state text NOT NULL DEFAULT 'started' CHECK (desired_state IN ('started','stopped','deleted')),
 observed_state text NOT NULL DEFAULT 'creating' CHECK (observed_state IN ('creating','starting','ready','stopping','stopped','deleting','deleted','error')),
 generation bigint NOT NULL DEFAULT 1 CHECK(generation>0),
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 UNIQUE(org_id,id),
 UNIQUE(org_id,creator_id,idempotency_key),
 FOREIGN KEY(org_id,template_id) REFERENCES sandbox_templates(org_id,id),
 FOREIGN KEY(org_id,peer_id) REFERENCES devices(org_id,id)
);
CREATE INDEX sandboxes_org_creator_idx ON sandboxes(org_id,creator_id) WHERE observed_state<>'deleted';

CREATE FUNCTION sandbox_immutable_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.id,NEW.org_id,NEW.creator_id,NEW.template_id,NEW.requested_scope,NEW.idempotency_key,NEW.request_hash,NEW.created_at,NEW.expires_at)
 IS DISTINCT FROM (OLD.id,OLD.org_id,OLD.creator_id,OLD.template_id,OLD.requested_scope,OLD.idempotency_key,OLD.request_hash,OLD.created_at,OLD.expires_at) THEN
  RAISE EXCEPTION 'sandbox identity and create intent are immutable';
 END IF;
 IF OLD.observed_state='deleted' AND (NEW.observed_state<>'deleted' OR NEW.desired_state<>'deleted') THEN
  RAISE EXCEPTION 'deleted sandbox cannot be resurrected';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sandbox_immutable_identity BEFORE UPDATE ON sandboxes FOR EACH ROW EXECUTE FUNCTION sandbox_immutable_identity();
CREATE FUNCTION sandbox_template_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-'enabled') IS DISTINCT FROM (to_jsonb(OLD)-'enabled') THEN
  RAISE EXCEPTION 'sandbox template revision is immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sandbox_template_immutable BEFORE UPDATE ON sandbox_templates FOR EACH ROW EXECUTE FUNCTION sandbox_template_immutable();

-- Deferred binding permits peer and sandbox association in one transaction,
-- but forbids an unbound sandbox peer or changing its kind/owner/org afterward.
CREATE FUNCTION sandbox_peer_binding() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE peer uuid; peers uuid[];
BEGIN
 IF TG_TABLE_NAME='sandboxes' THEN
  IF TG_OP='INSERT' THEN peers:=ARRAY[NEW.peer_id];
  ELSIF TG_OP='DELETE' THEN peers:=ARRAY[OLD.peer_id];
  ELSE peers:=ARRAY[NEW.peer_id,OLD.peer_id]; END IF;
 ELSE
  IF TG_OP='INSERT' THEN peers:=ARRAY[NEW.id];
  ELSIF TG_OP='DELETE' THEN peers:=ARRAY[OLD.id];
  ELSE peers:=ARRAY[NEW.id,OLD.id]; END IF;
 END IF;
 FOREACH peer IN ARRAY peers LOOP
  IF peer IS NULL THEN CONTINUE; END IF;
  IF EXISTS(SELECT 1 FROM sandboxes s JOIN devices d ON d.id=s.peer_id
    WHERE s.peer_id=peer AND (s.org_id<>d.org_id OR s.creator_id<>d.user_id OR d.kind<>'sandbox'
      OR (s.observed_state='deleted' AND d.status='active' AND d.deleted_at IS NULL)))
  OR EXISTS(SELECT 1 FROM devices d WHERE d.id=peer AND d.kind='sandbox'
    AND NOT EXISTS(SELECT 1 FROM sandboxes s WHERE s.peer_id=d.id)) THEN
   RAISE EXCEPTION 'sandbox peer requires matching sandbox organization and creator';
  END IF;
 END LOOP;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER sandbox_peer_binding_sandboxes AFTER INSERT OR UPDATE OR DELETE ON sandboxes
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sandbox_peer_binding();
CREATE CONSTRAINT TRIGGER sandbox_peer_binding_devices AFTER INSERT OR UPDATE OR DELETE ON devices
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sandbox_peer_binding();

-- Mesh policy is blanket access. Switching an org to mesh cannot be allowed to
-- widen a sandbox peer. Complete peer revocation/cleanup first.
ALTER TABLE organizations ADD CONSTRAINT sandboxes_enforcing_mode CHECK(NOT sandboxes_enabled OR zero_trust_mode='enforcing');
CREATE FUNCTION sandbox_enforcing_mode() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.zero_trust_mode<>'enforcing' AND EXISTS(SELECT 1 FROM sandboxes WHERE org_id=NEW.id AND observed_state<>'deleted') THEN
  RAISE EXCEPTION 'sandbox cleanup required before mesh policy';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sandbox_enforcing_mode BEFORE UPDATE OF zero_trust_mode ON organizations FOR EACH ROW EXECUTE FUNCTION sandbox_enforcing_mode();
CREATE FUNCTION sandbox_require_enforcing_mode() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM organizations WHERE id=NEW.org_id AND zero_trust_mode='enforcing' AND sandboxes_enabled) THEN
  RAISE EXCEPTION 'sandbox creation requires enforcing policy and opt-in';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sandbox_require_enforcing_mode BEFORE INSERT ON sandboxes FOR EACH ROW EXECUTE FUNCTION sandbox_require_enforcing_mode();
