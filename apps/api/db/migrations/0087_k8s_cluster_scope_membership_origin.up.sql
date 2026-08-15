-- Persist creation provenance for newly written cluster-scope memberships.
-- Existing 0086 rows deliberately remain NULL: status/audit text cannot
-- truthfully reconstruct whether they were selected initially or added later.
ALTER TABLE k8s_cluster_scope_memberships
    ADD COLUMN origin text CHECK (origin IN ('initial', 'later'));

CREATE FUNCTION k8s_cluster_scope_membership_origin_require_immutable() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.origin IS NULL OR NEW.origin NOT IN ('initial', 'later') THEN
            RAISE EXCEPTION 'k8s cluster scope membership origin is required for new rows';
        END IF;
        IF NEW.origin = 'initial' AND NEW.status <> 'approved' THEN
            RAISE EXCEPTION 'initial k8s cluster scope membership must be approved';
        END IF;
    ELSIF NEW.origin IS DISTINCT FROM OLD.origin THEN
        RAISE EXCEPTION 'k8s cluster scope membership origin is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER k8s_cluster_scope_memberships_origin_before_write
    BEFORE INSERT OR UPDATE OF origin ON k8s_cluster_scope_memberships
    FOR EACH ROW EXECUTE FUNCTION k8s_cluster_scope_membership_origin_require_immutable();
