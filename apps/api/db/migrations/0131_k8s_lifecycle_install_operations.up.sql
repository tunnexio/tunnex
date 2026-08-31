-- S20.5/D13h: provider-neutral install/abort linearization.
--
-- An operation is an append-only epoch for one exact lifecycle claim
-- generation/request. Mutable state is limited to heartbeat, durable abort
-- request, and terminal transitions. The control plane never stores a join
-- token, Kubernetes credential, or other secret in this table.

LOCK TABLE node_join_tokens IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE node_lifecycle_install_operations (
    operation_id               uuid PRIMARY KEY,
    token_id                   uuid NOT NULL REFERENCES node_join_tokens (id) ON DELETE CASCADE,
    org_id                     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    lifecycle_claim            uuid NOT NULL,
    lifecycle_generation       integer NOT NULL CHECK (lifecycle_generation > 0),
    lifecycle_request_id       uuid NOT NULL,
    epoch                      bigint NOT NULL CHECK (epoch > 0),
    release_namespace          text NOT NULL CHECK (btrim(release_namespace) <> '' AND length(release_namespace) <= 63),
    release_name               text NOT NULL CHECK (btrim(release_name) <> '' AND length(release_name) <= 42),
    install_intent_digest      text NOT NULL CHECK (install_intent_digest ~ '^sha256:[0-9a-f]{64}$'),
    requested_duration_seconds integer NOT NULL CHECK (requested_duration_seconds BETWEEN 1 AND 900),
    state                      text NOT NULL DEFAULT 'active'
                               CHECK (state IN ('active', 'released', 'completed', 'taken_over', 'aborted')),
    not_after                  timestamptz NOT NULL,
    heartbeat_at               timestamptz NOT NULL,
    abort_requested_at         timestamptz,
    released_at                timestamptz,
    completed_at               timestamptz,
    taken_over_at              timestamptz,
    aborted_at                 timestamptz,
    created_at                 timestamptz NOT NULL DEFAULT now(),
    updated_at                 timestamptz NOT NULL DEFAULT now(),
    UNIQUE (token_id, epoch),
    UNIQUE (org_id, lifecycle_claim, epoch),
    CHECK (heartbeat_at <= not_after),
    CHECK (created_at <= not_after),
    CHECK (
        (state = 'active'
            AND released_at IS NULL AND completed_at IS NULL
            AND taken_over_at IS NULL AND aborted_at IS NULL)
        OR
        (state = 'released'
            AND released_at IS NOT NULL AND completed_at IS NULL
            AND taken_over_at IS NULL AND aborted_at IS NULL)
        OR
        (state = 'completed'
            AND abort_requested_at IS NULL AND released_at IS NULL
            AND completed_at IS NOT NULL AND taken_over_at IS NULL
            AND aborted_at IS NULL)
        OR
        (state = 'taken_over'
            AND abort_requested_at IS NOT NULL AND released_at IS NULL
            AND completed_at IS NULL AND taken_over_at IS NOT NULL
            AND aborted_at IS NULL)
        OR
        (state = 'aborted'
            AND abort_requested_at IS NOT NULL AND completed_at IS NULL
            AND taken_over_at IS NOT NULL AND aborted_at IS NOT NULL)
    )
);

CREATE INDEX node_lifecycle_install_operations_claim_idx
    ON node_lifecycle_install_operations (org_id, lifecycle_claim, epoch DESC);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON node_lifecycle_install_operations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

REVOKE ALL ON node_lifecycle_install_operations FROM PUBLIC;

-- Like migration 0130, operation use makes rollback to an unaware application
-- unsafe even if the claim is later cascade-deleted. Persist that fact.
CREATE TABLE k8s_lifecycle_install_operation_usage (
    singleton          boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    first_persisted_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON k8s_lifecycle_install_operation_usage FROM PUBLIC;

CREATE FUNCTION mark_k8s_lifecycle_install_operation_usage() RETURNS trigger AS $$
BEGIN
    INSERT INTO public.k8s_lifecycle_install_operation_usage (singleton)
    VALUES (true)
    ON CONFLICT (singleton) DO NOTHING;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp;
REVOKE ALL ON FUNCTION mark_k8s_lifecycle_install_operation_usage() FROM PUBLIC;

CREATE TRIGGER node_lifecycle_install_operation_usage_after_insert
AFTER INSERT ON node_lifecycle_install_operations
FOR EACH ROW EXECUTE FUNCTION mark_k8s_lifecycle_install_operation_usage();

-- N-1 abort code does not know about install epochs. Make its existing
-- UPDATE observe zero rows whenever D13h owns the claim. A lifecycle-aware
-- replica must first drive the latest operation to terminal aborted while
-- holding the token lock. In particular, taken_over is still fenced: the new
-- CLI must prove the exact release/workloads absent through FinalizeAbort
-- before the claim/node can be revoked. Completed installs remain permanently
-- non-abortable.
CREATE FUNCTION node_lifecycle_guard_token_abort() RETURNS trigger AS $$
DECLARE
    latest_state text;
BEGIN
    IF OLD.lifecycle_aborted_at IS NULL
       AND NEW.lifecycle_aborted_at IS NOT NULL
       AND NEW.lifecycle_claim IS NOT NULL THEN
        SELECT operation.state
        INTO latest_state
        FROM public.node_lifecycle_install_operations operation
        WHERE operation.token_id = NEW.id
        ORDER BY operation.epoch DESC
        LIMIT 1
        FOR UPDATE;

        IF latest_state IS NOT NULL
           AND latest_state <> 'aborted' THEN
            RETURN NULL;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp;
REVOKE ALL ON FUNCTION node_lifecycle_guard_token_abort() FROM PUBLIC;

CREATE TRIGGER node_join_tokens_lifecycle_abort_guard_before_update
BEFORE UPDATE OF lifecycle_aborted_at ON node_join_tokens
FOR EACH ROW EXECUTE FUNCTION node_lifecycle_guard_token_abort();

-- D13a/N-1 remint knows nothing about operation epochs and could otherwise
-- rotate generation/request identity underneath an active or aborting holder.
-- Only a clean holder release (with no durable abort request) permits the next
-- expired-generation remint. The trigger returns NULL so the old application's
-- existing zero-row CAS path refuses safely.
CREATE FUNCTION node_lifecycle_guard_token_remint() RETURNS trigger AS $$
DECLARE
    latest_state text;
    latest_abort_requested_at timestamptz;
BEGIN
    IF NEW.lifecycle_claim IS NOT NULL
       AND (NEW.lifecycle_generation IS DISTINCT FROM OLD.lifecycle_generation
            OR NEW.lifecycle_request_id IS DISTINCT FROM OLD.lifecycle_request_id) THEN
        SELECT operation.state, operation.abort_requested_at
        INTO latest_state, latest_abort_requested_at
        FROM public.node_lifecycle_install_operations operation
        WHERE operation.token_id = NEW.id
        ORDER BY operation.epoch DESC
        LIMIT 1
        FOR UPDATE;

        IF latest_state IS NOT NULL
           AND (latest_state <> 'released' OR latest_abort_requested_at IS NOT NULL) THEN
            RETURN NULL;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp;
REVOKE ALL ON FUNCTION node_lifecycle_guard_token_remint() FROM PUBLIC;

CREATE TRIGGER node_join_tokens_lifecycle_remint_guard_before_update
BEFORE UPDATE OF lifecycle_generation, lifecycle_request_id ON node_join_tokens
FOR EACH ROW EXECUTE FUNCTION node_lifecycle_guard_token_remint();

-- Enrollment is itself part of the install authority. A stale gateway pod must
-- not consume the token after holder release, abort request, or hard deadline.
-- PostgreSQL runs same-kind triggers in name order: the `aa_` name is
-- intentionally before 0130's `...lifecycle_capture...` trigger so a refused
-- UPDATE cannot create a transaction-scoped enrollment authorization.
CREATE FUNCTION node_lifecycle_guard_token_consumption() RETURNS trigger AS $$
DECLARE
    latest_state text;
    latest_not_after timestamptz;
    latest_abort_requested_at timestamptz;
BEGIN
    IF OLD.consumed_at IS NULL
       AND NEW.consumed_at IS NOT NULL
       AND NEW.lifecycle_claim IS NOT NULL THEN
        SELECT operation.state, operation.not_after, operation.abort_requested_at
        INTO latest_state, latest_not_after, latest_abort_requested_at
        FROM public.node_lifecycle_install_operations operation
        WHERE operation.token_id = NEW.id
        ORDER BY operation.epoch DESC
        LIMIT 1
        FOR UPDATE;

        IF latest_state IS NOT NULL
           AND (latest_state <> 'active'
                OR latest_abort_requested_at IS NOT NULL
                OR latest_not_after <= clock_timestamp()) THEN
            RETURN NULL;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp;
REVOKE ALL ON FUNCTION node_lifecycle_guard_token_consumption() FROM PUBLIC;

CREATE TRIGGER node_join_tokens_aa_lifecycle_install_consume_guard_before_update
BEFORE UPDATE OF consumed_at ON node_join_tokens
FOR EACH ROW EXECUTE FUNCTION node_lifecycle_guard_token_consumption();
