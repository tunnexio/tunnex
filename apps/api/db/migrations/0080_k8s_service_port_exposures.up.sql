-- S10.3 P2: split a logical Kubernetes Service's stable VIP/DNS identity from its
-- exact-L4-port exposure children. A policy grant continues to reference a child
-- row, so adding a new port can never widen an existing grant.

CREATE TABLE k8s_service_identities (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    cluster_id uuid        NOT NULL REFERENCES k8s_clusters (id) ON DELETE CASCADE,
    name       text        NOT NULL,
    namespace  text        NOT NULL,
    vip        inet        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    -- The child FK includes the full logical identity tuple. A raw child update
    -- cannot move an exposure across cluster/name/namespace boundaries while
    -- retaining a parent ID or a shared VIP.
    UNIQUE (id, org_id, cluster_id, namespace, name, vip)
);

CREATE UNIQUE INDEX k8s_service_identities_ident_live
    ON k8s_service_identities (org_id, cluster_id, namespace, name)
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX k8s_service_identities_vip_live
    ON k8s_service_identities (org_id, cluster_id, vip)
    WHERE deleted_at IS NULL;
CREATE INDEX k8s_service_identities_org_idx
    ON k8s_service_identities (org_id) WHERE deleted_at IS NULL;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_service_identities
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Every existing single-port exposure becomes both the first child and its
-- parent identity. Grants keep their child UUID, VIP and exact-port semantics.
INSERT INTO k8s_service_identities
    (id, org_id, cluster_id, name, namespace, vip, created_at, updated_at, deleted_at)
SELECT id, org_id, cluster_id, name, namespace, vip, created_at, updated_at, deleted_at
FROM k8s_services;

ALTER TABLE k8s_services ADD COLUMN identity_id uuid;
UPDATE k8s_services SET identity_id = id;
ALTER TABLE k8s_services
    ADD CONSTRAINT k8s_services_identity_vip_fk
        FOREIGN KEY (identity_id, org_id, cluster_id, namespace, name, vip)
        REFERENCES k8s_service_identities (id, org_id, cluster_id, namespace, name, vip);

-- The insert trigger below fills old-writer inserts before constraints run.
-- Retain physical nullability for one rolling-upgrade release so an old
-- writer can omit the new column; the trigger and update guard make the
-- identity semantically non-null and non-detachable after backfill. A later
-- release may contract this to NOT NULL once every writer carries the field.

DROP INDEX k8s_services_ident_live;
DROP INDEX k8s_services_vip_live;

-- A child is unique only for the exact supported L4 exposure. COALESCE keeps
-- the index honest for pre-P2 legacy rows that carried NULL bounds.
CREATE UNIQUE INDEX k8s_services_port_exposure_live
    ON k8s_services (org_id, cluster_id, namespace, name, protocol,
                     COALESCE(port_low, 0), COALESCE(port_high, 0))
    WHERE deleted_at IS NULL;
CREATE INDEX k8s_services_identity_live_idx
    ON k8s_services (identity_id) WHERE deleted_at IS NULL;

-- Bind every new child to the one live logical Service identity. Concurrent
-- exposes converge through the live identity uniqueness; the child exact-port
-- index then distinguishes a duplicate request from a different port.
CREATE FUNCTION k8s_services_bind_identity() RETURNS trigger AS $$
DECLARE
    parent_id uuid;
    parent_vip inet;
BEGIN
    INSERT INTO k8s_service_identities (org_id, cluster_id, name, namespace, vip)
    VALUES (NEW.org_id, NEW.cluster_id, NEW.name, NEW.namespace, NEW.vip)
    ON CONFLICT (org_id, cluster_id, namespace, name) WHERE deleted_at IS NULL
    DO UPDATE SET updated_at = k8s_service_identities.updated_at
    RETURNING id, vip INTO parent_id, parent_vip;

    NEW.identity_id := parent_id;
    NEW.vip := parent_vip;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER k8s_services_bind_identity_before_insert
    BEFORE INSERT ON k8s_services
    FOR EACH ROW EXECUTE FUNCTION k8s_services_bind_identity();

-- A validated CHECK enforces the post-backfill non-null contract without the
-- rolling-upgrade break of ALTER COLUMN ... SET NOT NULL. Legacy inserts are
-- still safe because the BEFORE INSERT trigger has supplied the identity by
-- the time this constraint is evaluated.
ALTER TABLE k8s_services
    ADD CONSTRAINT k8s_services_identity_required CHECK (identity_id IS NOT NULL) NOT VALID;
ALTER TABLE k8s_services
    VALIDATE CONSTRAINT k8s_services_identity_required;

CREATE FUNCTION k8s_services_enforce_identity() RETURNS trigger AS $$
BEGIN
    IF NEW.identity_id IS NULL OR NEW.identity_id IS DISTINCT FROM OLD.identity_id THEN
        RAISE EXCEPTION 'k8s service exposure identity is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER k8s_services_enforce_identity_before_update
    BEFORE UPDATE OF identity_id ON k8s_services
    FOR EACH ROW EXECUTE FUNCTION k8s_services_enforce_identity();

-- The shared VIP/DNS identity remains live until its final exact-port child is
-- unexposed. Lock the parent row first: two transactions soft-deleting sibling
-- children then serialize, so the second re-check sees the first commit and
-- retires the now-empty identity. Re-expose creates a NEW identity/VIP, so old
-- child grants remain compiled-to-nothing and can never revive onto a different
-- Service.
CREATE FUNCTION k8s_services_retire_identity() RETURNS trigger AS $$
BEGIN
    IF OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL THEN
        PERFORM 1 FROM k8s_service_identities
        WHERE id = NEW.identity_id
        FOR UPDATE;

        IF NOT EXISTS (
            SELECT 1 FROM k8s_services
            WHERE identity_id = NEW.identity_id AND deleted_at IS NULL
        ) THEN
            UPDATE k8s_service_identities
            SET deleted_at = NEW.deleted_at
            WHERE id = NEW.identity_id AND deleted_at IS NULL;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER k8s_services_retire_identity_after_update
    AFTER UPDATE OF deleted_at ON k8s_services
    FOR EACH ROW EXECUTE FUNCTION k8s_services_retire_identity();
