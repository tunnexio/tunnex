-- Refuse destructive downgrade if sandbox state exists. Remove it through
-- qualified cleanup first; never silently drop running identities or templates.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM sandboxes) OR EXISTS(SELECT 1 FROM sandbox_templates) OR EXISTS(SELECT 1 FROM devices WHERE kind='sandbox') THEN
  RAISE EXCEPTION 'sandbox state must be cleaned before downgrade';
 END IF;
END $$;
DROP TRIGGER sandbox_peer_binding_devices ON devices;
DROP TRIGGER sandbox_enforcing_mode ON organizations;
DROP FUNCTION sandbox_enforcing_mode();
DROP FUNCTION sandbox_require_enforcing_mode() CASCADE;
ALTER TABLE organizations DROP CONSTRAINT sandboxes_enforcing_mode;
DROP TABLE sandboxes;
DROP TABLE sandbox_templates;
DROP FUNCTION sandbox_peer_binding();
DROP FUNCTION sandbox_immutable_identity();
DROP FUNCTION sandbox_template_immutable();
ALTER TABLE devices DROP CONSTRAINT devices_kind_check;
ALTER TABLE devices ADD CONSTRAINT devices_kind_check CHECK(kind IN ('human','agent'));
ALTER TABLE organizations DROP COLUMN sandboxes_enabled, DROP COLUMN max_sandboxes_per_user, DROP COLUMN max_sandboxes;
