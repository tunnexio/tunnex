-- An explicitly invoked qualification owns one canonical bounded workload.
-- It does not turn on ordinary organization or catalog provisioning.
CREATE TABLE sandbox_runner_qualification_trials (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 org_id uuid NOT NULL,
 enrollment_id uuid NOT NULL,
 sandbox_id uuid NOT NULL UNIQUE,
 creator_id uuid NOT NULL REFERENCES users(id),
 terminal_device_id uuid NOT NULL,
 profile_id uuid NOT NULL,
 template_id uuid NOT NULL,
 binding_hash bytea NOT NULL CHECK(octet_length(binding_hash)=32),
 spki_hash bytea NOT NULL CHECK(octet_length(spki_hash)=32),
 source_sha text NOT NULL CHECK(source_sha ~ '^[a-f0-9]{40}$'),
 image_digest text NOT NULL CHECK(image_digest ~ '^sha256:[a-f0-9]{64}$'),
 idempotency_key uuid NOT NULL,
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 phase text NOT NULL DEFAULT 'initial_ready' CHECK(phase IN ('initial_ready','stopped','resume_ready','awaiting_expiry','cleanup_pending','complete','failed')),
 runtime_id text,
 initial_ready_at timestamptz,
 stopped_at timestamptz,
 resume_ready_at timestamptz,
 retired_at timestamptz,
 offline_witness jsonb CHECK(jsonb_typeof(offline_witness)='object'),
 offline_witness_hash bytea CHECK(octet_length(offline_witness_hash)=32),
 failure_code text,
 FOREIGN KEY(org_id,enrollment_id) REFERENCES sandbox_runner_enrollments(org_id,id),
 FOREIGN KEY(org_id,sandbox_id) REFERENCES sandboxes(org_id,id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(org_id,terminal_device_id) REFERENCES devices(org_id,id),
 FOREIGN KEY(org_id,template_id) REFERENCES sandbox_templates(org_id,id),
 UNIQUE(org_id,id),
 UNIQUE(org_id,enrollment_id,idempotency_key),
 CHECK(expires_at=created_at+interval '900 seconds'),
 CHECK((offline_witness IS NULL)=(offline_witness_hash IS NULL))
);
CREATE INDEX sandbox_runner_qualification_trials_latest ON sandbox_runner_qualification_trials(org_id,enrollment_id,created_at DESC,id);

CREATE TABLE sandbox_runner_qualification_events (
 trial_id uuid NOT NULL REFERENCES sandbox_runner_qualification_trials(id),
 code text NOT NULL CHECK(code IN ('initial_ready','stopped','resume_ready','offline_expiry','retired')),
 generation bigint NOT NULL CHECK(generation>0),
 observed_at timestamptz NOT NULL,
 evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='object'),
 evidence_hash bytea NOT NULL CHECK(octet_length(evidence_hash)=32),
 PRIMARY KEY(trial_id,code)
);
CREATE FUNCTION sandbox_qualification_event_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'sandbox qualification receipts are immutable'; END $$;
CREATE TRIGGER sandbox_qualification_event_immutable BEFORE UPDATE OR DELETE ON sandbox_runner_qualification_events FOR EACH ROW EXECUTE FUNCTION sandbox_qualification_event_immutable();

CREATE FUNCTION sandbox_qualification_trial_grant_valid(trial uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(
 SELECT 1 FROM sandbox_runner_qualification_trials q
 JOIN sandbox_runner_enrollments e ON e.id=q.enrollment_id AND e.org_id=q.org_id
 JOIN organizations o ON o.id=q.org_id AND o.deleted_at IS NULL AND o.zero_trust_mode='enforcing'
 JOIN sandbox_templates t ON t.id=q.template_id AND t.org_id=q.org_id AND t.image_digest=q.image_digest
 JOIN memberships m ON m.org_id=q.org_id AND m.user_id=q.creator_id AND m.access_revoked_at IS NULL
 JOIN users u ON u.id=q.creator_id AND u.status='active' AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND NOT u.must_change_password
 JOIN memberships issuer ON issuer.org_id=q.org_id AND issuer.user_id=e.issuer_id AND issuer.access_revoked_at IS NULL
 JOIN users eu ON eu.id=issuer.user_id AND eu.status='active' AND eu.deleted_at IS NULL AND eu.email_verified_at IS NOT NULL AND NOT eu.must_change_password
 JOIN devices h ON h.id=q.terminal_device_id AND h.org_id=q.org_id AND h.user_id=q.creator_id
 WHERE q.id=trial AND q.phase NOT IN ('failed','complete') AND q.expires_at>now()
 AND e.consumed_at IS NOT NULL AND e.revoked_at IS NULL AND e.certificate_expires_at>now()
 AND e.profile_id=q.profile_id AND e.binding_hash=q.binding_hash AND e.spki_hash=q.spki_hash
 AND COALESCE(m.roles,ARRAY[m.role]) && ARRAY['admin','owner']::text[]
 AND COALESCE(issuer.roles,ARRAY[issuer.role]) && ARRAY['admin','owner']::text[]
 AND t.maximum_scope='[]'::jsonb AND t.memory_mib=128 AND t.max_ttl_seconds<=900
 AND h.kind='human' AND h.status='active' AND h.deleted_at IS NULL AND NOT h.health_blocked);
$$;

-- This exact predicate is the only exception to ordinary opt-in/catalog flags.
CREATE FUNCTION sandbox_qualification_trial_valid(workload uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM sandbox_runner_qualification_trials q
 JOIN sandboxes s ON s.id=q.sandbox_id AND s.org_id=q.org_id
 JOIN sandbox_runtime_bindings r ON r.sandbox_id=s.id AND r.org_id=s.org_id
 WHERE q.sandbox_id=workload AND sandbox_qualification_trial_grant_valid(q.id)
 AND s.creator_id=q.creator_id AND s.template_id=q.template_id AND s.terminal_device_id=q.terminal_device_id
 AND s.created_at=q.created_at AND s.expires_at=q.expires_at
 AND s.requested_scope='[]'::jsonb AND s.selected_skills='[]'::jsonb
 AND r.image_digest=q.image_digest AND r.memory_mib=128 AND r.cpus=1 AND r.pids=64);
$$;

-- Ordinary workloads retain their existing authority. A trial never falls
-- back to ordinary org flags after its narrower grant has been withdrawn.
CREATE FUNCTION sandbox_qualification_trial_authority(workload uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT NOT EXISTS(SELECT 1 FROM sandbox_runner_qualification_trials WHERE sandbox_id=workload)
 OR sandbox_qualification_trial_valid(workload);
$$;

-- The trial grant precedes insertion and has a deferred workload FK. Admission
-- checks NEW's exact immutable identity; the runtime predicate then joins the
-- canonical row and resource binding after the same transaction commits.
CREATE OR REPLACE FUNCTION sandbox_require_enforcing_mode() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM organizations o WHERE o.id=NEW.org_id AND o.zero_trust_mode='enforcing'
 AND (o.sandboxes_enabled OR EXISTS(SELECT 1 FROM sandbox_runner_qualification_trials q
 WHERE q.sandbox_id=NEW.id AND q.org_id=NEW.org_id AND q.creator_id=NEW.creator_id
 AND q.template_id=NEW.template_id AND q.terminal_device_id=NEW.terminal_device_id
 AND q.created_at=NEW.created_at AND q.expires_at=NEW.expires_at
 AND NEW.requested_scope='[]'::jsonb AND NEW.selected_skills='[]'::jsonb
 AND sandbox_qualification_trial_grant_valid(q.id)))) THEN
  RAISE EXCEPTION 'sandbox creation requires enforcing policy and opt-in or exact qualification grant';
 END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION sandbox_qualification_trial_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.org_id,NEW.enrollment_id,NEW.sandbox_id,NEW.creator_id,NEW.terminal_device_id,NEW.profile_id,NEW.template_id,NEW.binding_hash,NEW.spki_hash,NEW.source_sha,NEW.image_digest,NEW.idempotency_key,NEW.request_hash,NEW.created_at,NEW.expires_at)
 IS DISTINCT FROM ROW(OLD.id,OLD.org_id,OLD.enrollment_id,OLD.sandbox_id,OLD.creator_id,OLD.terminal_device_id,OLD.profile_id,OLD.template_id,OLD.binding_hash,OLD.spki_hash,OLD.source_sha,OLD.image_digest,OLD.idempotency_key,OLD.request_hash,OLD.created_at,OLD.expires_at)
 OR (OLD.runtime_id IS NOT NULL AND NEW.runtime_id IS DISTINCT FROM OLD.runtime_id)
 OR (OLD.initial_ready_at IS NOT NULL AND NEW.initial_ready_at IS DISTINCT FROM OLD.initial_ready_at)
 OR (OLD.stopped_at IS NOT NULL AND NEW.stopped_at IS DISTINCT FROM OLD.stopped_at)
 OR (OLD.resume_ready_at IS NOT NULL AND NEW.resume_ready_at IS DISTINCT FROM OLD.resume_ready_at)
 OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at)
 OR (OLD.offline_witness_hash IS NOT NULL AND ROW(NEW.offline_witness_hash,NEW.offline_witness) IS DISTINCT FROM ROW(OLD.offline_witness_hash,OLD.offline_witness))
 OR (OLD.phase='complete' AND NEW.phase<>'complete') THEN
  RAISE EXCEPTION 'sandbox qualification authority and observations are immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sandbox_qualification_trial_immutable BEFORE UPDATE ON sandbox_runner_qualification_trials FOR EACH ROW EXECUTE FUNCTION sandbox_qualification_trial_immutable();
