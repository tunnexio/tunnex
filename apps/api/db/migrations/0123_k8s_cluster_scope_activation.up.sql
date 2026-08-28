-- S20.4: activate the dormant 0086/0087 cluster-scope model behind an
-- enterprise unlock and an explicit, default-OFF organization opt-in.
-- Inventory is an immutable, connector-attributed snapshot; public callers
-- receive opaque references rather than Kubernetes Service UIDs.

-- 0113 re-authored these checks for FQDN destinations after the dormant 0086
-- scope migration. Re-expand the current shape; never regress either arm.
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_dst_kind_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_dst_kind_check
    CHECK (dst_kind IN ('resource','group','site','k8s_service','fqdn_resource','k8s_cluster_scope'));
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_check CHECK (
    (dst_kind='resource' AND dst_resource_id IS NOT NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL AND dst_k8s_cluster_id IS NULL)
 OR (dst_kind='group' AND dst_group_id IS NOT NULL AND dst_resource_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL AND dst_k8s_cluster_id IS NULL)
 OR (dst_kind='site' AND dst_site_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL AND dst_k8s_cluster_id IS NULL)
 OR (dst_kind='k8s_service' AND dst_k8s_service_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_fqdn_resource_id IS NULL AND dst_k8s_cluster_id IS NULL)
 OR (dst_kind='fqdn_resource' AND dst_fqdn_resource_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_k8s_cluster_id IS NULL)
 OR (dst_kind='k8s_cluster_scope' AND dst_k8s_cluster_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL)
);

CREATE TABLE k8s_cluster_scope_settings (
    org_id          uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE RESTRICT,
    enabled         boolean NOT NULL DEFAULT false,
    revision        bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    actor_user_id   uuid NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    cause           text NOT NULL CHECK (octet_length(btrim(cause)) BETWEEN 1 AND 200),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_cluster_scope_settings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE FUNCTION k8s_cluster_scope_setting_require_actor_membership() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM memberships m
        WHERE m.org_id=NEW.org_id AND m.user_id=NEW.actor_user_id
        FOR SHARE OF m
    ) THEN
        RAISE EXCEPTION 'k8s_cluster_scope_setting_actor_not_org_member';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_cluster_scope_settings_actor_before_write
    BEFORE INSERT OR UPDATE ON k8s_cluster_scope_settings
    FOR EACH ROW EXECUTE FUNCTION k8s_cluster_scope_setting_require_actor_membership();

CREATE TABLE k8s_service_inventory_reports (
    id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id              uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    site_id             uuid NOT NULL,
    cluster_id          uuid NOT NULL,
    connector_node_id   uuid NOT NULL,
    replay_state_id     uuid NOT NULL,
    replay_sequence     bigint NOT NULL CHECK (replay_sequence > 0),
    promotion_generation bigint NOT NULL CHECK (promotion_generation >= 0),
    digest              text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    service_count       integer NOT NULL CHECK (service_count BETWEEN 0 AND 500),
    observed_at         timestamptz NOT NULL,
    received_at         timestamptz NOT NULL DEFAULT now(),
    fresh_until         timestamptz NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (replay_state_id, replay_sequence),
    UNIQUE (id, org_id, cluster_id),
    FOREIGN KEY (cluster_id, org_id, site_id)
        REFERENCES k8s_clusters (id, org_id, site_id) ON DELETE CASCADE,
    FOREIGN KEY (connector_node_id, org_id, site_id)
        REFERENCES nodes (id, org_id, site_id) ON DELETE RESTRICT,
    FOREIGN KEY (replay_state_id, org_id)
        REFERENCES k8s_service_uid_observation_replay_states (id, org_id) ON DELETE CASCADE,
    CHECK (observed_at <= received_at + interval '5 seconds'),
    CHECK (fresh_until > received_at)
);
CREATE INDEX k8s_service_inventory_reports_current_idx
    ON k8s_service_inventory_reports (org_id, cluster_id, replay_sequence DESC, received_at DESC);

CREATE TABLE k8s_service_inventory_items (
    report_id       uuid NOT NULL,
    org_id          uuid NOT NULL,
    cluster_id      uuid NOT NULL,
    inventory_ref   uuid NOT NULL DEFAULT uuid_generate_v7(),
    namespace       text NOT NULL CHECK (namespace ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$' AND octet_length(namespace) BETWEEN 1 AND 63),
    service         text NOT NULL CHECK (service ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$' AND octet_length(service) BETWEEN 1 AND 63),
    service_uid     text NOT NULL CHECK (octet_length(service_uid) BETWEEN 1 AND 253 AND service_uid !~ '[[:cntrl:]]'),
    port_count      integer NOT NULL CHECK (port_count BETWEEN 1 AND 32),
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (report_id, namespace, service),
    UNIQUE (inventory_ref),
    UNIQUE (report_id, inventory_ref),
    FOREIGN KEY (report_id, org_id, cluster_id)
        REFERENCES k8s_service_inventory_reports (id, org_id, cluster_id) ON DELETE CASCADE
);
CREATE INDEX k8s_service_inventory_items_page_idx
    ON k8s_service_inventory_items (report_id, namespace, service, inventory_ref);

CREATE TABLE k8s_service_inventory_ports (
    report_id       uuid NOT NULL,
    inventory_ref   uuid NOT NULL,
    port_ref        uuid NOT NULL DEFAULT uuid_generate_v7(),
    name            text CHECK (name IS NULL OR (octet_length(name) BETWEEN 1 AND 63 AND name !~ '[[:cntrl:]]')),
    protocol        text NOT NULL CHECK (protocol IN ('tcp','udp')),
    service_port    integer NOT NULL CHECK (service_port BETWEEN 1 AND 65535),
    target_port     integer CHECK (target_port BETWEEN 1 AND 65535),
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (report_id, inventory_ref, port_ref),
    UNIQUE (report_id, inventory_ref, protocol, service_port),
    FOREIGN KEY (report_id, inventory_ref)
        REFERENCES k8s_service_inventory_items (report_id, inventory_ref) ON DELETE CASCADE
);

CREATE FUNCTION k8s_service_inventory_snapshot_immutable() RETURNS trigger AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        IF TG_TABLE_NAME='k8s_service_inventory_reports' THEN
            IF EXISTS (SELECT 1 FROM k8s_clusters c WHERE c.id=OLD.cluster_id AND c.org_id=OLD.org_id) THEN
                RAISE EXCEPTION 'k8s_service_inventory_snapshot_is_immutable';
            END IF;
        ELSIF TG_TABLE_NAME='k8s_service_inventory_items' THEN
            IF EXISTS (SELECT 1 FROM k8s_service_inventory_reports r WHERE r.id=OLD.report_id) THEN
                RAISE EXCEPTION 'k8s_service_inventory_snapshot_is_immutable';
            END IF;
        ELSIF TG_TABLE_NAME='k8s_service_inventory_ports' THEN
            IF EXISTS (SELECT 1 FROM k8s_service_inventory_items i WHERE i.report_id=OLD.report_id AND i.inventory_ref=OLD.inventory_ref) THEN
                RAISE EXCEPTION 'k8s_service_inventory_snapshot_is_immutable';
            END IF;
        END IF;
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'k8s_service_inventory_snapshot_is_immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_service_inventory_reports_immutable_before_change
    BEFORE UPDATE OR DELETE ON k8s_service_inventory_reports FOR EACH ROW
    EXECUTE FUNCTION k8s_service_inventory_snapshot_immutable();
CREATE TRIGGER k8s_service_inventory_items_immutable_before_change
    BEFORE UPDATE OR DELETE ON k8s_service_inventory_items FOR EACH ROW
    EXECUTE FUNCTION k8s_service_inventory_snapshot_immutable();
CREATE TRIGGER k8s_service_inventory_ports_immutable_before_change
    BEFORE UPDATE OR DELETE ON k8s_service_inventory_ports FOR EACH ROW
    EXECUTE FUNCTION k8s_service_inventory_snapshot_immutable();
CREATE FUNCTION k8s_service_inventory_refuse_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'k8s_service_inventory_snapshot_is_immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_service_inventory_reports_before_truncate BEFORE TRUNCATE ON k8s_service_inventory_reports
    FOR EACH STATEMENT EXECUTE FUNCTION k8s_service_inventory_refuse_truncate();
CREATE TRIGGER k8s_service_inventory_items_before_truncate BEFORE TRUNCATE ON k8s_service_inventory_items
    FOR EACH STATEMENT EXECUTE FUNCTION k8s_service_inventory_refuse_truncate();
CREATE TRIGGER k8s_service_inventory_ports_before_truncate BEFORE TRUNCATE ON k8s_service_inventory_ports
    FOR EACH STATEMENT EXECUTE FUNCTION k8s_service_inventory_refuse_truncate();

-- The stored counts are independently checked against their immutable child
-- sets. Writers insert children first through a deferred transaction and the
-- constraint triggers verify the final committed shape.
CREATE FUNCTION k8s_service_inventory_verify_counts() RETURNS trigger AS $$
DECLARE
    target_report uuid;
    target_ref uuid;
    expected integer;
    actual integer;
BEGIN
    IF TG_TABLE_NAME = 'k8s_service_inventory_reports' THEN
        expected := NEW.service_count;
        SELECT count(*) INTO actual FROM k8s_service_inventory_items WHERE report_id=NEW.id;
        IF actual <> expected THEN
            RAISE EXCEPTION 'k8s_service_inventory_service_count_mismatch';
        END IF;
    ELSIF TG_TABLE_NAME = 'k8s_service_inventory_items' THEN
        IF TG_OP='DELETE' THEN
            target_report := OLD.report_id;
            target_ref := OLD.inventory_ref;
        ELSE
            target_report := NEW.report_id;
            target_ref := NEW.inventory_ref;
        END IF;
        SELECT port_count INTO expected FROM k8s_service_inventory_items
          WHERE report_id=target_report AND inventory_ref=target_ref;
        IF expected IS NULL THEN
            IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
        END IF;
        SELECT count(*) INTO actual FROM k8s_service_inventory_ports
          WHERE report_id=target_report AND inventory_ref=target_ref;
        IF actual <> expected THEN
            RAISE EXCEPTION 'k8s_service_inventory_port_count_mismatch';
        END IF;
        SELECT service_count INTO expected FROM k8s_service_inventory_reports
          WHERE id=target_report;
        SELECT count(*) INTO actual FROM k8s_service_inventory_items WHERE report_id=target_report;
        IF actual <> expected THEN
            RAISE EXCEPTION 'k8s_service_inventory_service_count_mismatch';
        END IF;
    ELSE
        IF TG_OP='DELETE' THEN
            target_report := OLD.report_id;
            target_ref := OLD.inventory_ref;
        ELSE
            target_report := NEW.report_id;
            target_ref := NEW.inventory_ref;
        END IF;
        SELECT port_count INTO expected FROM k8s_service_inventory_items
          WHERE report_id=target_report AND inventory_ref=target_ref;
        IF expected IS NULL THEN
            IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
        END IF;
        SELECT count(*) INTO actual FROM k8s_service_inventory_ports
          WHERE report_id=target_report AND inventory_ref=target_ref;
        IF actual <> expected THEN
            RAISE EXCEPTION 'k8s_service_inventory_port_count_mismatch';
        END IF;
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER k8s_service_inventory_reports_count_after_write
    AFTER INSERT OR UPDATE OF service_count ON k8s_service_inventory_reports
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION k8s_service_inventory_verify_counts();
CREATE CONSTRAINT TRIGGER k8s_service_inventory_items_count_after_write
    AFTER INSERT OR UPDATE OR DELETE ON k8s_service_inventory_items
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION k8s_service_inventory_verify_counts();
CREATE CONSTRAINT TRIGGER k8s_service_inventory_ports_count_after_write
    AFTER INSERT OR UPDATE OR DELETE ON k8s_service_inventory_ports
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION k8s_service_inventory_verify_counts();

-- A report must be from the exact selected active connector and must agree
-- with the current replay high-watermark. A stale/moved/revoked reporter can
-- retain history but cannot publish a new inventory snapshot.
CREATE FUNCTION k8s_service_inventory_require_current_reporter() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM k8s_service_uid_observation_replay_states r
        JOIN k8s_clusters c
          ON c.id=NEW.cluster_id AND c.org_id=NEW.org_id AND c.site_id=NEW.site_id
        JOIN nodes n
          ON n.id=NEW.connector_node_id AND n.org_id=NEW.org_id AND n.site_id=NEW.site_id
        WHERE r.id=NEW.replay_state_id AND r.org_id=NEW.org_id
          AND r.site_id=NEW.site_id AND r.cluster_id=NEW.cluster_id
          AND r.connector_node_id=NEW.connector_node_id
          AND r.sequence=NEW.replay_sequence
          AND n.status='active' AND n.revoked_at IS NULL
          AND (
            (c.connector_pool_id IS NULL AND c.connector_node_id=NEW.connector_node_id
             AND NEW.promotion_generation=0)
            OR
            (c.connector_node_id IS NULL AND EXISTS (
                SELECT 1 FROM k8s_connector_pools p
                JOIN k8s_connector_pool_members m
                  ON m.pool_id=p.id AND m.org_id=p.org_id AND m.site_id=p.site_id
                 AND m.node_id=p.active_node_id
                WHERE p.id=c.connector_pool_id AND p.org_id=c.org_id
                  AND p.site_id=c.site_id AND p.cluster_id=c.id
                  AND p.active_node_id=NEW.connector_node_id
                  AND p.generation=NEW.promotion_generation AND p.generation>0
                FOR SHARE OF p,m
            ))
          )
        FOR SHARE OF r,c,n
    ) THEN
        RAISE EXCEPTION 'k8s_service_inventory_reporter_not_current';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_service_inventory_reports_reporter_before_write
    BEFORE INSERT OR UPDATE OF org_id,site_id,cluster_id,connector_node_id,replay_state_id,replay_sequence
    ON k8s_service_inventory_reports FOR EACH ROW
    EXECUTE FUNCTION k8s_service_inventory_require_current_reporter();

-- Every inventory item must match the exact current, attributed UID observed
-- at this report's replay sequence. The UID remains private server evidence.
CREATE FUNCTION k8s_service_inventory_require_current_uid() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM k8s_service_inventory_reports report
        JOIN k8s_service_uid_observation_ledgers l
          ON l.org_id=report.org_id AND l.cluster_id=report.cluster_id
        JOIN k8s_service_uid_observation_current current_uid
          ON current_uid.ledger_id=l.id AND current_uid.org_id=l.org_id
         AND current_uid.namespace=NEW.namespace AND current_uid.service=NEW.service
        JOIN k8s_service_uid_observation_current_attributions a
          ON a.ledger_id=current_uid.ledger_id AND a.org_id=current_uid.org_id
         AND a.namespace=current_uid.namespace AND a.service=current_uid.service
         AND a.replay_state_id=report.replay_state_id
         AND a.replay_sequence=report.replay_sequence
        WHERE report.id=NEW.report_id AND report.org_id=NEW.org_id
          AND report.cluster_id=NEW.cluster_id
          AND current_uid.uid=NEW.service_uid AND current_uid.state='live'
          AND current_uid.replay_sequence=report.replay_sequence
        FOR SHARE OF report,l,current_uid,a
    ) THEN
        RAISE EXCEPTION 'k8s_service_inventory_uid_not_current';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_service_inventory_items_uid_before_insert
    BEFORE INSERT ON k8s_service_inventory_items FOR EACH ROW
    EXECUTE FUNCTION k8s_service_inventory_require_current_uid();

-- Preserve the offered initial set, including explicit non-selection. These
-- rows are evidence, not entitlement; only approved memberships compile.
CREATE TABLE k8s_cluster_scope_initial_candidates (
    rule_id             uuid NOT NULL,
    org_id              uuid NOT NULL,
    cluster_id          uuid NOT NULL,
    service_child_id    uuid NOT NULL REFERENCES k8s_services (id) ON DELETE RESTRICT,
    inventory_report_id uuid NOT NULL,
    namespace           text NOT NULL,
    service_uid         text NOT NULL,
    protocol            text NOT NULL CHECK (protocol IN ('tcp','udp')),
    port_low            integer NOT NULL CHECK (port_low BETWEEN 1 AND 65535),
    port_high           integer NOT NULL CHECK (port_high=port_low),
    selected            boolean NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, service_child_id),
    FOREIGN KEY (rule_id, org_id, cluster_id)
        REFERENCES k8s_cluster_scope_grants (rule_id, org_id, cluster_id) ON DELETE CASCADE,
    CONSTRAINT k8s_cluster_scope_initial_candidates_inventory_report_fkey
        FOREIGN KEY (inventory_report_id, org_id, cluster_id)
        REFERENCES k8s_service_inventory_reports (id, org_id, cluster_id) ON DELETE RESTRICT
);
CREATE INDEX k8s_cluster_scope_initial_candidates_scope_idx
    ON k8s_cluster_scope_initial_candidates (org_id, cluster_id, rule_id, service_child_id);
CREATE INDEX k8s_cluster_scope_initial_candidates_inventory_report_idx
    ON k8s_cluster_scope_initial_candidates (inventory_report_id);

CREATE FUNCTION k8s_cluster_scope_initial_candidate_immutable() RETURNS trigger AS $$
BEGIN
    -- Only the owning policy-rule cascade may erase this durable evidence.
    -- A direct grant delete also hides the parent grant before its child
    -- cascade runs, so checking the grant alone would permit evidence loss.
    IF TG_OP='DELETE'
       AND NOT EXISTS (SELECT 1 FROM k8s_cluster_scope_grants g WHERE g.rule_id=OLD.rule_id)
       AND NOT EXISTS (SELECT 1 FROM policy_rules r WHERE r.id=OLD.rule_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'k8s_cluster_scope_initial_candidate_is_immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_cluster_scope_initial_candidates_before_update
    BEFORE UPDATE OR DELETE ON k8s_cluster_scope_initial_candidates FOR EACH ROW
    EXECUTE FUNCTION k8s_cluster_scope_initial_candidate_immutable();
CREATE TRIGGER k8s_cluster_scope_initial_candidates_before_truncate
    BEFORE TRUNCATE ON k8s_cluster_scope_initial_candidates FOR EACH STATEMENT
    EXECUTE FUNCTION k8s_service_inventory_refuse_truncate();

CREATE FUNCTION k8s_cluster_scope_initial_candidate_require_identity() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM k8s_services s
        JOIN k8s_service_identities i
          ON i.id=s.identity_id AND i.org_id=s.org_id AND i.cluster_id=s.cluster_id
        JOIN k8s_service_inventory_reports report
          ON report.id=NEW.inventory_report_id AND report.org_id=s.org_id
         AND report.cluster_id=s.cluster_id
        JOIN k8s_service_inventory_items inventory
          ON inventory.report_id=report.id AND inventory.org_id=s.org_id
         AND inventory.cluster_id=s.cluster_id
         AND inventory.namespace=s.namespace AND inventory.service=i.name
         AND inventory.service_uid=NEW.service_uid
        JOIN k8s_service_inventory_ports inventory_port
          ON inventory_port.report_id=inventory.report_id
         AND inventory_port.inventory_ref=inventory.inventory_ref
         AND inventory_port.protocol=NEW.protocol
         AND inventory_port.service_port=NEW.port_low
        JOIN k8s_service_uid_observation_ledgers l
          ON l.org_id=s.org_id AND l.cluster_id=s.cluster_id
        JOIN k8s_service_uid_observation_current current_uid
          ON current_uid.ledger_id=l.id AND current_uid.org_id=l.org_id
         AND current_uid.namespace=s.namespace AND current_uid.service=i.name
        JOIN k8s_service_uid_observation_current_attributions a
          ON a.ledger_id=current_uid.ledger_id AND a.org_id=current_uid.org_id
         AND a.namespace=current_uid.namespace AND a.service=current_uid.service
         AND a.replay_state_id=report.replay_state_id
         AND a.replay_sequence=current_uid.replay_sequence
        JOIN k8s_service_uid_observation_replay_states replay
          ON replay.id=report.replay_state_id AND replay.org_id=report.org_id
         AND replay.site_id=report.site_id AND replay.cluster_id=report.cluster_id
         AND replay.connector_node_id=report.connector_node_id
        JOIN k8s_clusters cluster
          ON cluster.id=report.cluster_id AND cluster.org_id=report.org_id
         AND cluster.site_id=report.site_id
        JOIN nodes reporter
          ON reporter.id=report.connector_node_id AND reporter.org_id=report.org_id
         AND reporter.site_id=report.site_id
        WHERE s.id=NEW.service_child_id AND s.org_id=NEW.org_id
          AND s.cluster_id=NEW.cluster_id AND s.deleted_at IS NULL
          AND s.namespace=NEW.namespace AND current_uid.uid=NEW.service_uid
          AND current_uid.state='live' AND s.protocol=NEW.protocol
          AND s.port_low=NEW.port_low AND s.port_high=NEW.port_high
          AND report.fresh_until>now()
          AND report.replay_sequence=replay.sequence
          AND report.replay_sequence=current_uid.replay_sequence
          AND reporter.status='active' AND reporter.revoked_at IS NULL
          AND (
            (cluster.connector_pool_id IS NULL
             AND cluster.connector_node_id=report.connector_node_id
             AND report.promotion_generation=0)
            OR
            (cluster.connector_node_id IS NULL AND EXISTS (
                SELECT 1
                FROM k8s_connector_pools pool
                JOIN k8s_connector_pool_members member
                  ON member.pool_id=pool.id AND member.org_id=pool.org_id
                 AND member.site_id=pool.site_id AND member.node_id=pool.active_node_id
                WHERE pool.id=cluster.connector_pool_id
                  AND pool.org_id=cluster.org_id AND pool.site_id=cluster.site_id
                  AND pool.cluster_id=cluster.id
                  AND pool.active_node_id=report.connector_node_id
                  AND pool.generation=report.promotion_generation
                  AND pool.generation>0
                FOR SHARE OF pool,member
            ))
          )
        FOR SHARE OF s,i,inventory,report,inventory_port,l,current_uid,a,replay,cluster,reporter
    ) THEN
        RAISE EXCEPTION 'k8s_cluster_scope_initial_candidate_identity_invalid';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_cluster_scope_initial_candidates_identity_before_insert
    BEFORE INSERT ON k8s_cluster_scope_initial_candidates FOR EACH ROW
    EXECUTE FUNCTION k8s_cluster_scope_initial_candidate_require_identity();

CREATE FUNCTION k8s_cluster_scope_verify_initial_snapshot() RETURNS trigger AS $$
DECLARE
    target_rule uuid;
    expected integer;
    actual integer;
    selected_count integer;
    membership_count integer;
BEGIN
    IF TG_OP='DELETE' THEN target_rule := OLD.rule_id; ELSE target_rule := NEW.rule_id; END IF;
    SELECT initial_candidate_count INTO expected FROM k8s_cluster_scope_grants WHERE rule_id=target_rule;
    IF expected IS NULL THEN
        IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END IF;
    SELECT count(*), count(*) FILTER (WHERE selected)
      INTO actual, selected_count
      FROM k8s_cluster_scope_initial_candidates WHERE rule_id=target_rule;
    IF actual <> expected THEN
        RAISE EXCEPTION 'k8s_cluster_scope_initial_candidate_count_mismatch';
    END IF;
    IF selected_count > 100 THEN
        RAISE EXCEPTION 'k8s_cluster_scope_initial_selection_limit_reached';
    END IF;
    SELECT count(*) INTO membership_count FROM k8s_cluster_scope_memberships
      WHERE rule_id=target_rule AND origin='initial' AND status='approved';
    IF membership_count <> selected_count OR EXISTS (
        SELECT 1 FROM k8s_cluster_scope_initial_candidates c
        WHERE c.rule_id=target_rule AND c.selected
          AND NOT EXISTS (
            SELECT 1 FROM k8s_cluster_scope_memberships m
            WHERE m.rule_id=c.rule_id AND m.service_child_id=c.service_child_id
              AND m.origin='initial' AND m.status='approved'
          )
    ) THEN
        RAISE EXCEPTION 'k8s_cluster_scope_initial_selection_membership_mismatch';
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER k8s_cluster_scope_initial_candidates_verify_after_write
    AFTER INSERT OR DELETE ON k8s_cluster_scope_initial_candidates
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION k8s_cluster_scope_verify_initial_snapshot();
CREATE CONSTRAINT TRIGGER k8s_cluster_scope_grants_initial_snapshot_after_write
    AFTER INSERT OR UPDATE OF initial_candidate_count ON k8s_cluster_scope_grants
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION k8s_cluster_scope_verify_initial_snapshot();
CREATE CONSTRAINT TRIGGER k8s_cluster_scope_memberships_initial_snapshot_after_write
    AFTER INSERT OR UPDATE OR DELETE ON k8s_cluster_scope_memberships
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION k8s_cluster_scope_verify_initial_snapshot();

-- Queue and terminal decisions are durable history. Permit their deletion
-- only when the owning policy rule itself is being deleted; deleting a grant
-- directly must not use its child cascade to erase evidence while leaving a
-- dangling cluster-scope policy rule behind.
CREATE FUNCTION k8s_cluster_scope_membership_refuse_direct_delete() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM k8s_cluster_scope_grants g WHERE g.rule_id=OLD.rule_id)
       AND NOT EXISTS (SELECT 1 FROM policy_rules r WHERE r.id=OLD.rule_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'k8s_cluster_scope_membership_is_durable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_cluster_scope_memberships_before_delete
    BEFORE DELETE ON k8s_cluster_scope_memberships FOR EACH ROW
    EXECUTE FUNCTION k8s_cluster_scope_membership_refuse_direct_delete();
CREATE TRIGGER k8s_cluster_scope_memberships_before_truncate
    BEFORE TRUNCATE ON k8s_cluster_scope_memberships FOR EACH STATEMENT
    EXECUTE FUNCTION k8s_service_inventory_refuse_truncate();

-- Serialize membership cardinality on the scope, not on distinct child rows,
-- so concurrent later exposures cannot each observe capacity below 500.
CREATE FUNCTION k8s_cluster_scope_serialize_membership_capacity() RETURNS trigger AS $$
BEGIN
    PERFORM 1 FROM k8s_cluster_scope_grants WHERE rule_id=NEW.rule_id FOR UPDATE;
    IF (SELECT count(*) FROM k8s_cluster_scope_memberships WHERE rule_id=NEW.rule_id) >= 500 THEN
        RAISE EXCEPTION 'k8s_cluster_scope_membership_limit_reached';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER a_k8s_cluster_scope_memberships_capacity_before_insert
    BEFORE INSERT ON k8s_cluster_scope_memberships FOR EACH ROW
    EXECUTE FUNCTION k8s_cluster_scope_serialize_membership_capacity();

ALTER TABLE k8s_cluster_scope_grants
    DROP CONSTRAINT k8s_cluster_scope_grants_initial_candidate_count_check;
ALTER TABLE k8s_cluster_scope_grants
    ADD CONSTRAINT k8s_cluster_scope_grants_initial_candidate_count_check
    CHECK (initial_candidate_count BETWEEN 0 AND 500),
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0);

-- Deregistration must never silently cascade a governance object introduced
-- after an older client was released.
ALTER TABLE k8s_cluster_scope_grants
    DROP CONSTRAINT k8s_cluster_scope_grants_cluster_id_fkey;
ALTER TABLE k8s_cluster_scope_grants
    ADD CONSTRAINT k8s_cluster_scope_grants_cluster_id_fkey
    FOREIGN KEY (cluster_id) REFERENCES k8s_clusters (id) ON DELETE RESTRICT;
