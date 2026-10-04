CREATE TABLE app_access_installation_authority (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 generation uuid NOT NULL DEFAULT uuid_generate_v7(),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 changed_at timestamptz NOT NULL DEFAULT now(),
 recovery_completed_at timestamptz DEFAULT now()
);
INSERT INTO app_access_installation_authority DEFAULT VALUES;

CREATE TABLE app_access_session_revocations (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL,
 app_id uuid NOT NULL,
 user_id uuid NOT NULL,
 live_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
 session_id uuid NOT NULL,
 installation_generation uuid NOT NULL,
 absolute_expires_at timestamptz NOT NULL,
 revoked_at timestamptz NOT NULL DEFAULT now(),
 actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
 actor_system text CHECK(actor_system IS NULL OR actor_system IN('app-access-recovery')),
 actor_user_snapshot uuid,
 reason text NOT NULL CHECK(reason IN('self','admin','recovery')),
 UNIQUE(org_id,app_id,user_id,session_id,installation_generation),
 FOREIGN KEY(org_id,app_id) REFERENCES app_access_applications(org_id,id) ON DELETE RESTRICT,
 CHECK(live_user_id IS NULL OR live_user_id=user_id),
 CHECK((actor_user_snapshot IS NOT NULL AND actor_system IS NULL) OR (actor_user_snapshot IS NULL AND actor_system IS NOT NULL)),
 CHECK(actor_user_id IS NULL OR actor_user_id=actor_user_snapshot),
 CHECK((reason='recovery')=(actor_system IS NOT NULL)),
 CHECK(reason<>'self' OR actor_user_snapshot=user_id)
);
CREATE INDEX app_access_session_revocations_user_session ON app_access_session_revocations(org_id,user_id,session_id,revoked_at DESC,id DESC);
CREATE INDEX app_access_session_revocations_app_session ON app_access_session_revocations(org_id,app_id,session_id,revoked_at DESC,id DESC);
CREATE INDEX app_access_session_revocations_history ON app_access_session_revocations(org_id,app_id,revoked_at DESC,id DESC);
CREATE FUNCTION app_access_session_revocation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF ROW(NEW.org_id,NEW.app_id,NEW.user_id,NEW.session_id,NEW.installation_generation,NEW.absolute_expires_at,NEW.revoked_at,NEW.actor_user_snapshot,NEW.actor_system,NEW.reason)
 IS DISTINCT FROM ROW(OLD.org_id,OLD.app_id,OLD.user_id,OLD.session_id,OLD.installation_generation,OLD.absolute_expires_at,OLD.revoked_at,OLD.actor_user_snapshot,OLD.actor_system,OLD.reason) THEN RAISE EXCEPTION 'App Access session revocation is immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER app_access_session_revocation_immutable BEFORE UPDATE ON app_access_session_revocations FOR EACH ROW EXECUTE FUNCTION app_access_session_revocation_immutable();

CREATE TABLE app_access_events (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL,
 app_id uuid NOT NULL,
 installation_generation uuid NOT NULL,
 revision bigint CHECK(revision IS NULL OR revision>0),
 serving_generation uuid,
 user_id uuid,
 gateway_id uuid,
 proxy_id uuid,
 session_id uuid,
 stream_id uuid,
 correlation_id uuid,
 event_kind text NOT NULL CHECK(event_kind IN('launch_created','session_created','session_revoked','request_allowed','request_denied','stream_renewed','stream_denied','stream_terminated','publication_changed','recovery','gap')),
 outcome text NOT NULL CHECK(outcome IN('allowed','denied','completed','revoked','failed','gap')),
 reason text NOT NULL CHECK(reason IN('none','session_invalid','parent_unavailable','user_inactive','membership_unavailable','no_use_permission','no_active_grant','feature_disabled','feature_unavailable','publication_unavailable','installation_changed','session_revoked','lease_expired','connection_closed','self','admin','recovery','infrastructure_unavailable','dropped_events')),
 dropped_count bigint NOT NULL DEFAULT 0 CHECK(dropped_count>=0 AND (event_kind='gap' OR dropped_count=0)),
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(org_id,app_id) REFERENCES app_access_applications(org_id,id) ON DELETE RESTRICT
);
CREATE INDEX app_access_events_history ON app_access_events(org_id,created_at DESC,id DESC);
CREATE INDEX app_access_events_app_history ON app_access_events(org_id,app_id,created_at DESC,id DESC);
CREATE INDEX app_access_events_user_history ON app_access_events(org_id,user_id,created_at DESC,id DESC) WHERE user_id IS NOT NULL;
CREATE INDEX app_access_events_session_history ON app_access_events(org_id,session_id,created_at DESC,id DESC) WHERE session_id IS NOT NULL;
