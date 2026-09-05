LOCK TABLE k8s_base_authority_deliveries IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM k8s_base_authority_deliveries
        WHERE authority_kind = 'ordinary_base'
    ) THEN
        RAISE EXCEPTION 'cannot roll back 0134: ordinary-base authority deliveries exist';
    END IF;
END $$;

DROP INDEX k8s_base_authority_deliveries_transition_replay_idx;

ALTER TABLE k8s_base_authority_deliveries
    DROP CONSTRAINT k8s_base_authority_deliveries_kind_revision_check,
    ALTER COLUMN transition_revision SET NOT NULL,
    ADD CONSTRAINT k8s_base_authority_deliveries_transition_revision_check CHECK (transition_revision > 0),
    DROP COLUMN authority_kind;
