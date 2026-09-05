-- S20.3b D4/D5: transition evidence and ordinary-base maintenance have
-- different replay semantics. Keep them in disjoint durable namespaces so a
-- later maintain_fence refresh cannot collide with (or satisfy) an operator
-- transition revision for the same node/pool.
ALTER TABLE k8s_base_authority_deliveries
    ADD COLUMN authority_kind text NOT NULL DEFAULT 'transition';

ALTER TABLE k8s_base_authority_deliveries
    DROP CONSTRAINT k8s_base_authority_deliveries_transition_revision_check,
    ALTER COLUMN transition_revision DROP NOT NULL;

ALTER TABLE k8s_base_authority_deliveries
    ADD CONSTRAINT k8s_base_authority_deliveries_kind_revision_check
    CHECK ((authority_kind = 'transition' AND transition_revision > 0)
        OR (authority_kind = 'ordinary_base' AND transition_revision IS NULL));

CREATE INDEX k8s_base_authority_deliveries_transition_replay_idx
    ON k8s_base_authority_deliveries
       (org_id, site_id, node_id, authority_kind, transition_revision, authority_revision DESC);
