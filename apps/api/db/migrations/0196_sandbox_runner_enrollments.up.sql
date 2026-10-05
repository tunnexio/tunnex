-- One configured organization runner slot; no user, machine or routing grants.
CREATE TABLE sandbox_runner_enrollments (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 org_id uuid NOT NULL REFERENCES organizations(id),
 issuer_id uuid NOT NULL REFERENCES users(id),
 profile_id uuid NOT NULL,
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 80),
 idempotency_key uuid NOT NULL,
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
 binding_hash bytea NOT NULL CHECK(octet_length(binding_hash)=32),
 token_hash bytea NOT NULL CHECK(octet_length(token_hash)=32),
 runner_uri text NOT NULL CHECK(length(runner_uri) BETWEEN 1 AND 512),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 spki_hash bytea CHECK(octet_length(spki_hash)=32),
 probe_public_key text CHECK(length(probe_public_key) BETWEEN 1 AND 1024),
 certificate text CHECK(length(certificate) BETWEEN 1 AND 16384),
 certificate_expires_at timestamptz,
 revoked_at timestamptz,
 revoke_reason text,
 last_seen_at timestamptz,
 ready_at timestamptz,
 UNIQUE(org_id,id),
 UNIQUE(org_id,issuer_id,idempotency_key),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '10 minutes'),
 CHECK((consumed_at IS NULL AND spki_hash IS NULL AND probe_public_key IS NULL AND certificate IS NULL AND certificate_expires_at IS NULL)
 OR (consumed_at IS NOT NULL AND spki_hash IS NOT NULL AND probe_public_key IS NOT NULL AND certificate IS NOT NULL AND certificate_expires_at IS NOT NULL))
);
CREATE INDEX sandbox_runner_enrollments_org_created ON sandbox_runner_enrollments(org_id,created_at DESC,id);

CREATE TABLE sandbox_runner_workloads (
 sandbox_id uuid PRIMARY KEY,
 org_id uuid NOT NULL,
 enrollment_id uuid NOT NULL,
 FOREIGN KEY(org_id,sandbox_id) REFERENCES sandboxes(org_id,id),
 FOREIGN KEY(org_id,enrollment_id) REFERENCES sandbox_runner_enrollments(org_id,id)
);
CREATE INDEX sandbox_runner_workloads_grant ON sandbox_runner_workloads(org_id,enrollment_id);

CREATE TABLE sandbox_runner_qualification_reports (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 org_id uuid NOT NULL,
 enrollment_id uuid NOT NULL,
 spki_hash bytea NOT NULL CHECK(octet_length(spki_hash)=32),
 binding_hash bytea NOT NULL CHECK(octet_length(binding_hash)=32),
 report_hash bytea NOT NULL CHECK(octet_length(report_hash)=32),
 report jsonb NOT NULL CHECK(jsonb_typeof(report)='object'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 decision text NOT NULL DEFAULT 'pending' CHECK(decision IN ('pending','approved','rejected')),
 reviewed_by uuid REFERENCES users(id),
 reviewed_at timestamptz,
 review_note text CHECK(length(review_note)<=512),
 FOREIGN KEY(org_id,enrollment_id) REFERENCES sandbox_runner_enrollments(org_id,id),
 UNIQUE(org_id,enrollment_id,report_hash),
 CHECK((decision='pending' AND reviewed_by IS NULL AND reviewed_at IS NULL) OR (decision<>'pending' AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL))
);
CREATE INDEX sandbox_runner_qualification_latest ON sandbox_runner_qualification_reports(org_id,enrollment_id,created_at DESC,id);

CREATE FUNCTION sandbox_runner_enrollment_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.org_id,NEW.issuer_id,NEW.profile_id,NEW.name,NEW.idempotency_key,NEW.request_hash,NEW.binding_hash,NEW.token_hash,NEW.runner_uri,NEW.created_at,NEW.expires_at)
 IS DISTINCT FROM ROW(OLD.id,OLD.org_id,OLD.issuer_id,OLD.profile_id,OLD.name,OLD.idempotency_key,OLD.request_hash,OLD.binding_hash,OLD.token_hash,OLD.runner_uri,OLD.created_at,OLD.expires_at)
 OR (OLD.consumed_at IS NOT NULL AND ROW(NEW.consumed_at,NEW.spki_hash,NEW.probe_public_key,NEW.certificate) IS DISTINCT FROM ROW(OLD.consumed_at,OLD.spki_hash,OLD.probe_public_key,OLD.certificate))
 OR (OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR NEW.certificate_expires_at IS DISTINCT FROM OLD.certificate_expires_at)) THEN
  RAISE EXCEPTION 'sandbox runner enrollment authority is immutable';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER sandbox_runner_enrollment_immutable BEFORE UPDATE ON sandbox_runner_enrollments FOR EACH ROW EXECUTE FUNCTION sandbox_runner_enrollment_immutable();

CREATE FUNCTION sandbox_runner_workload_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'sandbox runner workload binding is immutable'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER sandbox_runner_workload_immutable BEFORE UPDATE ON sandbox_runner_workloads FOR EACH ROW EXECUTE FUNCTION sandbox_runner_workload_immutable();

CREATE FUNCTION sandbox_runner_qualification_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.org_id,NEW.enrollment_id,NEW.spki_hash,NEW.binding_hash,NEW.report_hash,NEW.report,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.id,OLD.org_id,OLD.enrollment_id,OLD.spki_hash,OLD.binding_hash,OLD.report_hash,OLD.report,OLD.created_at)
 OR (OLD.decision<>'pending' AND NEW IS DISTINCT FROM OLD) THEN
  RAISE EXCEPTION 'sandbox runner qualification evidence/review is immutable';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER sandbox_runner_qualification_immutable BEFORE UPDATE ON sandbox_runner_qualification_reports FOR EACH ROW EXECUTE FUNCTION sandbox_runner_qualification_immutable();
