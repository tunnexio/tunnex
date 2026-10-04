-- Additive defaults do not rewrite prior immutable configuration digests.
ALTER TABLE app_access_revisions ADD COLUMN allowed_destination_cidrs text[] NOT NULL DEFAULT '{}';
ALTER TABLE app_access_revisions ADD COLUMN origin_ca_pem text NOT NULL DEFAULT '' CHECK(octet_length(origin_ca_pem)<=32768);
ALTER TABLE app_access_revisions ADD COLUMN origin_ca_digest text NOT NULL DEFAULT '' CHECK(origin_ca_digest='' OR length(origin_ca_digest)=64);
ALTER TABLE app_access_revisions ADD CONSTRAINT app_access_origin_cidr_limit CHECK(cardinality(allowed_destination_cidrs)<=32);
ALTER TABLE app_access_revisions ADD CONSTRAINT app_access_revision_connector_tuple UNIQUE(org_id,app_id,gateway_id,revision,digest);
CREATE TABLE app_access_gateway_runtime (
 org_id uuid NOT NULL,
 gateway_id uuid NOT NULL,
 capability_version integer NOT NULL DEFAULT 0 CHECK(capability_version BETWEEN 0 AND 65535),
 reported_cert_serial text NOT NULL,
 reported_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(org_id,gateway_id),
 FOREIGN KEY(org_id,gateway_id) REFERENCES nodes(org_id,id) ON DELETE CASCADE
);
CREATE TABLE app_access_connector_assignments (
 generation uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL,
 app_id uuid NOT NULL,
 gateway_id uuid NOT NULL,
 revision bigint NOT NULL,
 digest text NOT NULL CHECK(length(digest)=64),
 purpose text NOT NULL DEFAULT 'origin_check' CHECK(purpose='origin_check'),
 withdrawn_at timestamptz,
 applied_status text NOT NULL DEFAULT 'pending' CHECK(applied_status IN ('pending','configured','failed','withdrawn')),
 applied_error_code text NOT NULL DEFAULT '',
 applied_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(org_id,app_id,gateway_id,revision,digest) REFERENCES app_access_revisions(org_id,app_id,gateway_id,revision,digest) ON DELETE CASCADE,
 FOREIGN KEY(org_id,gateway_id) REFERENCES nodes(org_id,id) ON DELETE CASCADE,
 UNIQUE(org_id,app_id,gateway_id,revision,digest,generation,purpose)
);
CREATE UNIQUE INDEX app_access_assignment_current ON app_access_connector_assignments(org_id,app_id,purpose) WHERE withdrawn_at IS NULL;
CREATE TABLE app_access_origin_checks (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL,
 app_id uuid NOT NULL,
 gateway_id uuid NOT NULL,
 revision bigint NOT NULL,
 digest text NOT NULL CHECK(length(digest)=64),
 generation uuid NOT NULL,
 purpose text NOT NULL DEFAULT 'origin_check' CHECK(purpose='origin_check'),
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','failed','expired','withdrawn')),
 dns_status text NOT NULL DEFAULT 'pending' CHECK(dns_status IN ('pending','passed','failed')),
 connect_status text NOT NULL DEFAULT 'pending' CHECK(connect_status IN ('pending','passed','failed')),
 tls_status text NOT NULL DEFAULT 'pending' CHECK(tls_status IN ('pending','passed','failed','skipped')),
 error_code text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now(),
 deadline timestamptz NOT NULL DEFAULT now()+interval '10 seconds',
 completed_at timestamptz,
 FOREIGN KEY(org_id,app_id,gateway_id,revision,digest,generation,purpose) REFERENCES app_access_connector_assignments(org_id,app_id,gateway_id,revision,digest,generation,purpose) ON DELETE CASCADE,
 CHECK(deadline>created_at AND deadline<=created_at+interval '10 seconds')
);
CREATE INDEX app_access_checks_pending ON app_access_origin_checks(org_id,gateway_id,status,created_at);
CREATE INDEX app_access_checks_app_history ON app_access_origin_checks(org_id,app_id,created_at DESC);

CREATE FUNCTION app_access_connector_tuple_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF ROW(NEW.org_id,NEW.app_id,NEW.gateway_id,NEW.revision,NEW.digest,NEW.generation,NEW.purpose) IS DISTINCT FROM ROW(OLD.org_id,OLD.app_id,OLD.gateway_id,OLD.revision,OLD.digest,OLD.generation,OLD.purpose) THEN RAISE EXCEPTION 'App Access connector authority tuple is immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER app_access_assignment_immutable BEFORE UPDATE ON app_access_connector_assignments FOR EACH ROW EXECUTE FUNCTION app_access_connector_tuple_immutable();
CREATE TRIGGER app_access_check_immutable BEFORE UPDATE ON app_access_origin_checks FOR EACH ROW EXECUTE FUNCTION app_access_connector_tuple_immutable();
