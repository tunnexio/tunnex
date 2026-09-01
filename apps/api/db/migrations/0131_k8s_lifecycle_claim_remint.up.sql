-- S20.5/D13a: crash-consistent Kubernetes gateway enrollment recovery.
--
-- The opaque lifecycle claim is the immutable identity shared by the
-- Kubernetes bootstrap Secret, its one-time join-token row, and the eventual
-- node. The raw token remains recoverable only while a remint response has not
-- been acknowledged by Kubernetes and has not been consumed by enrollment.

-- Enrollment updates the token and then inserts the node in one transaction.
-- Take the same lock order before either ALTER so an in-flight N-1 enrollment
-- cannot deadlock this migration by holding node_join_tokens while waiting for
-- nodes. These locks are deliberately held for the whole migration.
LOCK TABLE node_join_tokens IN ACCESS EXCLUSIVE MODE;
LOCK TABLE nodes IN ACCESS EXCLUSIVE MODE;

ALTER TABLE nodes
    ADD COLUMN lifecycle_claim uuid;

CREATE UNIQUE INDEX nodes_lifecycle_claim_key
    ON nodes (lifecycle_claim)
    WHERE lifecycle_claim IS NOT NULL;

ALTER TABLE node_join_tokens
    ADD COLUMN lifecycle_claim uuid,
    ADD COLUMN lifecycle_generation integer NOT NULL DEFAULT 0,
    ADD COLUMN lifecycle_request_id uuid,
    ADD COLUMN lifecycle_token_sealed text,
    ADD COLUMN lifecycle_acknowledged_at timestamptz,
    ADD COLUMN lifecycle_aborted_at timestamptz,
    ADD CONSTRAINT node_join_tokens_lifecycle_generation_check
        CHECK (lifecycle_generation >= 0),
    ADD CONSTRAINT node_join_tokens_lifecycle_shape_check
        CHECK (
            (lifecycle_claim IS NULL
                AND lifecycle_generation = 0
                AND lifecycle_request_id IS NULL
                AND lifecycle_token_sealed IS NULL
                AND lifecycle_acknowledged_at IS NULL
                AND lifecycle_aborted_at IS NULL)
            OR
            (lifecycle_claim IS NOT NULL
                AND lifecycle_generation > 0
                AND lifecycle_request_id IS NOT NULL)
            OR
            (lifecycle_claim IS NOT NULL
                AND lifecycle_generation = 0
                AND lifecycle_request_id IS NOT NULL
                AND node_name IS NOT NULL
                AND btrim(node_name) <> ''
                AND lifecycle_token_sealed IS NULL
                AND lifecycle_acknowledged_at IS NULL
                AND lifecycle_aborted_at IS NOT NULL
                AND consumed_at IS NULL
                AND consumed_node_id IS NULL)
        );

CREATE UNIQUE INDEX node_join_tokens_lifecycle_claim_key
    ON node_join_tokens (lifecycle_claim)
    WHERE lifecycle_claim IS NOT NULL;

-- A lifecycle claim makes this schema forward-only even after the associated
-- token and revoked node are later deleted. Live-row emptiness cannot prove
-- that the old application is safe again, so persist a migration-owned usage
-- sentinel on the first claim-bearing token or node write.
CREATE TABLE k8s_lifecycle_claim_usage (
    singleton          boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    first_persisted_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON k8s_lifecycle_claim_usage FROM PUBLIC;

CREATE FUNCTION mark_k8s_lifecycle_claim_usage() RETURNS trigger AS $$
BEGIN
    INSERT INTO public.k8s_lifecycle_claim_usage (singleton)
    VALUES (true)
    ON CONFLICT (singleton) DO NOTHING;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp;
REVOKE ALL ON FUNCTION mark_k8s_lifecycle_claim_usage() FROM PUBLIC;

CREATE TRIGGER node_join_tokens_lifecycle_usage_after_insert
AFTER INSERT ON node_join_tokens
FOR EACH ROW WHEN (NEW.lifecycle_claim IS NOT NULL)
EXECUTE FUNCTION mark_k8s_lifecycle_claim_usage();

CREATE TRIGGER node_join_tokens_lifecycle_usage_after_update
AFTER UPDATE OF lifecycle_claim ON node_join_tokens
FOR EACH ROW WHEN (NEW.lifecycle_claim IS NOT NULL AND OLD.lifecycle_claim IS DISTINCT FROM NEW.lifecycle_claim)
EXECUTE FUNCTION mark_k8s_lifecycle_claim_usage();

CREATE TRIGGER nodes_lifecycle_usage_after_insert
AFTER INSERT ON nodes
FOR EACH ROW WHEN (NEW.lifecycle_claim IS NOT NULL)
EXECUTE FUNCTION mark_k8s_lifecycle_claim_usage();

CREATE TRIGGER nodes_lifecycle_usage_after_update
AFTER UPDATE OF lifecycle_claim ON nodes
FOR EACH ROW WHEN (NEW.lifecycle_claim IS NOT NULL AND OLD.lifecycle_claim IS DISTINCT FROM NEW.lifecycle_claim)
EXECUTE FUNCTION mark_k8s_lifecycle_claim_usage();

-- D13b: an N-1 replica knows neither lifecycle_claim column. During a rolling
-- control-plane deployment it still performs ConsumeJoinToken and CreateNode in
-- one transaction, so bridge that exact transaction at the database boundary.
-- This table must be empty in every committed state: consumption creates one
-- authorization and the matching node insert consumes it; the deferred trigger
-- below rejects commit if either half is missing.
CREATE TABLE node_lifecycle_enrollment_authorizations (
    backend_pid     integer NOT NULL,
    transaction_id bigint NOT NULL,
    token_id        uuid NOT NULL REFERENCES node_join_tokens (id) ON DELETE CASCADE,
    org_id          uuid NOT NULL,
    node_name       text NOT NULL,
    lifecycle_claim uuid NOT NULL,
    PRIMARY KEY (backend_pid, transaction_id, token_id)
);
REVOKE ALL ON node_lifecycle_enrollment_authorizations FROM PUBLIC;

-- Capture only the first NULL -> non-NULL consumption transition. Clearing the
-- sealed response here is as important as copying the claim: the N-1 statement
-- predates lifecycle_token_sealed and otherwise leaves a consumed raw token
-- recoverable through exact-request redelivery.
CREATE FUNCTION node_lifecycle_capture_consumption() RETURNS trigger AS $$
BEGIN
    IF OLD.consumed_at IS NULL
       AND NEW.consumed_at IS NOT NULL
       AND NEW.lifecycle_claim IS NOT NULL THEN
        -- N-1 does not know lifecycle_aborted_at and therefore cannot put the
        -- abort predicate in its UPDATE. Make the old statement observe zero
        -- rows (its existing invalid-token path), never a database error or a
        -- resurrected claim. The lifecycle-aware statement filters this row
        -- before the trigger.
        IF NEW.lifecycle_aborted_at IS NOT NULL THEN
            RETURN NULL;
        END IF;
        IF NEW.node_name IS NULL OR btrim(NEW.node_name) = '' OR NEW.consumed_node_id IS NOT NULL THEN
            RAISE EXCEPTION 'node_lifecycle_consumption_identity_is_malformed'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;

        NEW.lifecycle_token_sealed := NULL;
        INSERT INTO public.node_lifecycle_enrollment_authorizations
            (backend_pid, transaction_id, token_id, org_id, node_name, lifecycle_claim)
        VALUES
            (pg_backend_pid(), txid_current(), NEW.id, NEW.org_id, NEW.node_name, NEW.lifecycle_claim);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp;
REVOKE ALL ON FUNCTION node_lifecycle_capture_consumption() FROM PUBLIC;

CREATE TRIGGER node_join_tokens_lifecycle_capture_before_update
BEFORE UPDATE OF consumed_at ON node_join_tokens
FOR EACH ROW EXECUTE FUNCTION node_lifecycle_capture_consumption();

-- N passes the immutable claim explicitly; N-1 inserts NULL because its SQL
-- predates the column. Both must consume exactly one same-transaction
-- authorization pinned to the same organization and node name. No name-only,
-- timestamp, latest-row, or cross-session inference is accepted.
CREATE FUNCTION node_lifecycle_bind_claim_before_insert() RETURNS trigger AS $$
DECLARE
    transaction_authorizations integer;
    matching_authorizations integer;
    authorized_claim uuid;
BEGIN
    SELECT count(*)
    INTO transaction_authorizations
    FROM public.node_lifecycle_enrollment_authorizations a
    WHERE a.backend_pid = pg_backend_pid()
      AND a.transaction_id = txid_current();

    IF transaction_authorizations = 0 THEN
        IF NEW.lifecycle_claim IS NOT NULL THEN
            RAISE EXCEPTION 'node_lifecycle_claim_has_no_transaction_authorization'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        RETURN NEW;
    END IF;

    SELECT count(*), min(a.lifecycle_claim::text)::uuid
    INTO matching_authorizations, authorized_claim
    FROM public.node_lifecycle_enrollment_authorizations a
    WHERE a.backend_pid = pg_backend_pid()
      AND a.transaction_id = txid_current()
      AND a.org_id = NEW.org_id
      AND a.node_name = NEW.name
      AND (NEW.lifecycle_claim IS NULL OR a.lifecycle_claim = NEW.lifecycle_claim);

    IF matching_authorizations <> 1 OR authorized_claim IS NULL THEN
        RAISE EXCEPTION 'node_lifecycle_enrollment_authorization_missing_or_ambiguous'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.lifecycle_claim IS NOT NULL AND NEW.lifecycle_claim <> authorized_claim THEN
        RAISE EXCEPTION 'node_lifecycle_claim_mismatch'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    NEW.lifecycle_claim := authorized_claim;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp;
REVOKE ALL ON FUNCTION node_lifecycle_bind_claim_before_insert() FROM PUBLIC;

CREATE TRIGGER nodes_lifecycle_claim_bind_before_insert
BEFORE INSERT ON nodes
FOR EACH ROW EXECUTE FUNCTION node_lifecycle_bind_claim_before_insert();

-- The FK from token to node is immediate, so link only after the node exists.
-- The BEFORE trigger already fixed NEW.lifecycle_claim; the globally unique
-- claim now identifies the exact authorization without mutable-name inference.
CREATE FUNCTION node_lifecycle_link_token_after_insert() RETURNS trigger AS $$
DECLARE
    authorized_token uuid;
    affected_rows integer;
BEGIN
    IF NEW.lifecycle_claim IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT a.token_id
    INTO authorized_token
    FROM public.node_lifecycle_enrollment_authorizations a
    WHERE a.backend_pid = pg_backend_pid()
      AND a.transaction_id = txid_current()
      AND a.org_id = NEW.org_id
      AND a.node_name = NEW.name
      AND a.lifecycle_claim = NEW.lifecycle_claim;

    IF authorized_token IS NULL THEN
        RAISE EXCEPTION 'node_lifecycle_claim_has_no_exact_token_authorization'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    UPDATE public.node_join_tokens token
    SET consumed_node_id = NEW.id
    WHERE token.id = authorized_token
      AND token.org_id = NEW.org_id
      AND token.node_name = NEW.name
      AND token.lifecycle_claim = NEW.lifecycle_claim
      AND token.consumed_at IS NOT NULL
      AND token.consumed_node_id IS NULL
      AND token.lifecycle_aborted_at IS NULL;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows <> 1 THEN
        RAISE EXCEPTION 'node_lifecycle_token_link_compare_and_swap_failed'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    DELETE FROM public.node_lifecycle_enrollment_authorizations a
    WHERE a.backend_pid = pg_backend_pid()
      AND a.transaction_id = txid_current()
      AND a.token_id = authorized_token
      AND a.org_id = NEW.org_id
      AND a.node_name = NEW.name
      AND a.lifecycle_claim = NEW.lifecycle_claim;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows <> 1 THEN
        RAISE EXCEPTION 'node_lifecycle_authorization_consume_compare_and_swap_failed'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp;
REVOKE ALL ON FUNCTION node_lifecycle_link_token_after_insert() FROM PUBLIC;

CREATE TRIGGER nodes_lifecycle_token_link_after_insert
AFTER INSERT ON nodes
FOR EACH ROW EXECUTE FUNCTION node_lifecycle_link_token_after_insert();

-- This is the crash/partial-statement backstop. It re-reads current rows when
-- the deferred event fires; the queued NEW record predates the node-link update
-- and therefore is not itself sufficient evidence.
CREATE FUNCTION node_lifecycle_verify_consumption_bound() RETURNS trigger AS $$
DECLARE
    exact_binding boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM public.node_join_tokens token
        JOIN public.nodes node ON node.id = token.consumed_node_id
        WHERE token.id = NEW.id
          AND token.consumed_at IS NOT NULL
          AND token.lifecycle_claim IS NOT NULL
          AND token.org_id = node.org_id
          AND token.node_name = node.name
          AND token.lifecycle_claim = node.lifecycle_claim
    ) AND NOT EXISTS (
        SELECT 1
        FROM public.node_lifecycle_enrollment_authorizations a
        WHERE a.backend_pid = pg_backend_pid()
          AND a.transaction_id = txid_current()
          AND a.token_id = NEW.id
    )
    INTO exact_binding;

    IF NOT exact_binding THEN
        RAISE EXCEPTION 'node_lifecycle_consumption_is_not_bound_to_exact_node'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp;
REVOKE ALL ON FUNCTION node_lifecycle_verify_consumption_bound() FROM PUBLIC;

CREATE CONSTRAINT TRIGGER node_lifecycle_consumption_must_bind
AFTER UPDATE ON node_join_tokens
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL AND NEW.lifecycle_claim IS NOT NULL)
EXECUTE FUNCTION node_lifecycle_verify_consumption_bound();
