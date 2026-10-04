ALTER TABLE app_access_applications DROP CONSTRAINT app_access_applications_state_check;
ALTER TABLE app_access_applications ADD CONSTRAINT app_access_applications_state_check CHECK(state IN ('draft','archived'));
ALTER TABLE app_access_origin_checks ADD COLUMN completed_cert_serial text NOT NULL DEFAULT '';
ALTER TABLE app_access_origin_checks ADD CONSTRAINT app_access_check_publication_tuple UNIQUE(org_id,app_id,gateway_id,revision,digest,id,purpose);
ALTER TABLE app_access_revisions ADD CONSTRAINT app_access_revision_publication_host UNIQUE(org_id,app_id,gateway_id,revision,digest,public_hostname);
CREATE TABLE app_access_browser_gateway_runtime (
 org_id uuid NOT NULL,
 gateway_id uuid NOT NULL,
 capability_version integer NOT NULL DEFAULT 0 CHECK(capability_version BETWEEN 0 AND 65535),
 reported_cert_serial text NOT NULL,
 reported_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(org_id,gateway_id),
 FOREIGN KEY(org_id,gateway_id) REFERENCES nodes(org_id,id) ON DELETE CASCADE
);
CREATE TABLE app_access_publication_operations (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL,
 app_id uuid NOT NULL,
 actor_user_id uuid NOT NULL REFERENCES users(id),
 idempotency_key uuid NOT NULL,
 reviewed_app_version bigint NOT NULL CHECK(reviewed_app_version>0),
 expected_app_version bigint NOT NULL CHECK(expected_app_version=reviewed_app_version+1),
 revision bigint NOT NULL,
 digest text NOT NULL CHECK(length(digest)=64),
 origin_check_id uuid NOT NULL,
 origin_check_purpose text NOT NULL DEFAULT 'origin_check' CHECK(origin_check_purpose='origin_check'),
 gateway_id uuid NOT NULL,
 hostname text NOT NULL,
 generation uuid NOT NULL UNIQUE DEFAULT uuid_generate_v7(),
 purpose text NOT NULL DEFAULT 'browser_proxy' CHECK(purpose='browser_proxy'),
 expected_active_authority_version bigint NOT NULL CHECK(expected_active_authority_version>=0),
 authority_version bigint NOT NULL CHECK(authority_version=expected_active_authority_version+1),
 gateway_cert_serial text NOT NULL CHECK(length(gateway_cert_serial) BETWEEN 1 AND 256),
 readiness_request_id uuid NOT NULL UNIQUE DEFAULT uuid_generate_v7(),
 proxy_instance_token_hash bytea CHECK(proxy_instance_token_hash IS NULL OR octet_length(proxy_instance_token_hash)=32),
 deadline timestamptz NOT NULL,
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 status text NOT NULL DEFAULT 'queued' CHECK(status IN('queued','checking','activated','failed','cancelled','expired')),
 proxy_credential_id uuid REFERENCES app_access_proxy_credentials(id),
 proxy_credential_version bigint CHECK(proxy_credential_version>0),
 claimed_at timestamptz,
 origin_proof_completed_at timestamptz,
 public_proof_completed_at timestamptz,
 completed_at timestamptz,
 public_dns_status text NOT NULL DEFAULT 'pending' CHECK(public_dns_status IN('pending','passed','failed')),
 public_tls_status text NOT NULL DEFAULT 'pending' CHECK(public_tls_status IN('pending','passed','failed')),
 connector_dns_status text NOT NULL DEFAULT 'pending' CHECK(connector_dns_status IN('pending','passed','failed')),
 connector_connect_status text NOT NULL DEFAULT 'pending' CHECK(connector_connect_status IN('pending','passed','failed')),
 connector_tls_status text NOT NULL DEFAULT 'pending' CHECK(connector_tls_status IN('pending','passed','failed','skipped')),
 error_code text NOT NULL DEFAULT '' CHECK(error_code IN('','public_dns_failed','public_tls_failed','public_challenge_failed','connector_failed','dns_failed','target_refused','connect_failed','tls_failed','http_failed','deadline_exceeded','assignment_changed','capability_unavailable','origin_check_stale','publication_changed','proxy_unavailable')),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(org_id,app_id,idempotency_key),
 FOREIGN KEY(org_id,app_id,gateway_id,revision,digest,hostname) REFERENCES app_access_revisions(org_id,app_id,gateway_id,revision,digest,public_hostname) ON DELETE RESTRICT,
 FOREIGN KEY(org_id,app_id,gateway_id,revision,digest,origin_check_id,origin_check_purpose) REFERENCES app_access_origin_checks(org_id,app_id,gateway_id,revision,digest,id,purpose) ON DELETE RESTRICT,
 CHECK(deadline>created_at AND deadline<=created_at+interval '60 seconds'),
 CHECK((proxy_credential_id IS NULL AND proxy_credential_version IS NULL AND proxy_instance_token_hash IS NULL) OR (proxy_credential_id IS NOT NULL AND proxy_credential_version IS NOT NULL AND proxy_instance_token_hash IS NOT NULL))
);
CREATE UNIQUE INDEX app_access_publication_pending ON app_access_publication_operations(org_id,app_id) WHERE status IN('queued','checking');
CREATE INDEX app_access_publication_work ON app_access_publication_operations(status,deadline,created_at);
CREATE INDEX app_access_publication_history ON app_access_publication_operations(org_id,app_id,created_at DESC,id DESC);
CREATE FUNCTION app_access_publication_operation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF ROW(NEW.org_id,NEW.app_id,NEW.actor_user_id,NEW.idempotency_key,NEW.reviewed_app_version,NEW.expected_app_version,NEW.revision,NEW.digest,NEW.origin_check_id,NEW.origin_check_purpose,NEW.gateway_id,NEW.hostname,NEW.generation,NEW.purpose,NEW.expected_active_authority_version,NEW.authority_version,NEW.gateway_cert_serial,NEW.readiness_request_id,NEW.deadline,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.org_id,OLD.app_id,OLD.actor_user_id,OLD.idempotency_key,OLD.reviewed_app_version,OLD.expected_app_version,OLD.revision,OLD.digest,OLD.origin_check_id,OLD.origin_check_purpose,OLD.gateway_id,OLD.hostname,OLD.generation,OLD.purpose,OLD.expected_active_authority_version,OLD.authority_version,OLD.gateway_cert_serial,OLD.readiness_request_id,OLD.deadline,OLD.created_at) THEN RAISE EXCEPTION 'App Access publication operation tuple is immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER app_access_publication_operation_immutable BEFORE UPDATE ON app_access_publication_operations FOR EACH ROW EXECUTE FUNCTION app_access_publication_operation_immutable();

ALTER TABLE app_access_serving_publications ADD COLUMN withdrawal_confirmed_at timestamptz;
ALTER TABLE app_access_serving_publications ADD COLUMN withdrawal_confirmed_authority_version bigint;
ALTER TABLE app_access_serving_publications ADD COLUMN withdrawal_confirmed_generation uuid;
ALTER TABLE app_access_serving_publications ADD CONSTRAINT app_access_withdrawal_confirmation CHECK(
 (withdrawal_confirmed_at IS NULL AND withdrawal_confirmed_authority_version IS NULL AND withdrawal_confirmed_generation IS NULL)
 OR (withdrawal_confirmed_at IS NOT NULL AND withdrawal_confirmed_authority_version IS NOT NULL AND withdrawal_confirmed_generation IS NOT NULL AND state='disabled' AND withdrawal_confirmed_authority_version=authority_version AND withdrawal_confirmed_generation=generation));
