-- VAULT-UX-1 (docs/VAULT-UX-1-vault-experience.md).
-- V5: details edits do not create a secret version, so they need their own
-- optimistic-concurrency counter. Every change to an entry bumps it.
ALTER TABLE vault_entries ADD COLUMN revision integer NOT NULL DEFAULT 1 CHECK (revision > 0);

-- V18: retention pruning scans quick requests by age.
CREATE INDEX vault_quick_requests_created ON vault_quick_requests(created_at);

-- V6 (founder decision): a person's PERSONAL entries leave with their membership.
-- A trigger owned by Vault covers every removal path (hard removal and directory
-- access revocation) in the same transaction, without tenancy code importing Vault.
-- Assigned entries the person created stay: they belong to the organization's audience.
-- Deactivation keeps the membership and is deliberately not a purge.
CREATE FUNCTION vault_purge_personal_entries(p_org uuid, p_user uuid, p_reason text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    purged integer;
BEGIN
    DELETE FROM vault_entries
     WHERE org_id = p_org AND owner_user_id = p_user AND visibility = 'personal';
    GET DIAGNOSTICS purged = ROW_COUNT;
    -- No titles: organization audit is readable by administrators, who must not
    -- learn what was in someone's personal Vault. Skipped while the organization
    -- itself is being deleted.
    IF purged > 0 AND EXISTS (SELECT 1 FROM organizations WHERE id = p_org) THEN
        INSERT INTO audit_logs(org_id, actor_system, action, target_type, target_id, metadata)
        VALUES (p_org, 'vault', 'vault.personal_entries_purged', 'user', p_user::text,
                jsonb_build_object('entries', purged, 'reason', p_reason));
    END IF;
END;
$$;

CREATE FUNCTION vault_purge_on_membership_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM vault_purge_personal_entries(OLD.org_id, OLD.user_id, 'membership_removed');
    RETURN OLD;
END;
$$;

CREATE FUNCTION vault_purge_on_membership_revoke() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM vault_purge_personal_entries(NEW.org_id, NEW.user_id, 'organization_access_revoked');
    RETURN NEW;
END;
$$;

CREATE TRIGGER vault_purge_personal_on_membership_delete AFTER DELETE ON memberships
    FOR EACH ROW EXECUTE FUNCTION vault_purge_on_membership_delete();
CREATE TRIGGER vault_purge_personal_on_membership_revoke AFTER UPDATE OF access_revoked_at ON memberships
    FOR EACH ROW WHEN (OLD.access_revoked_at IS NULL AND NEW.access_revoked_at IS NOT NULL)
    EXECUTE FUNCTION vault_purge_on_membership_revoke();
