-- S10.2 Slice 3a: the ownership marker. A nullable managed_by_machine records the MACHINE credential that
-- created an object via the operator (GitOps). NULL for dashboard/human-created objects — INERT, no behavior
-- change (the zero-config golden's ownership analog). The dashboard SURFACE (a managed badge + warn-on-edit,
-- D2) lands in Slice 4; the marker is recorded NOW so that surface never requires a retrofit-migration of
-- live rows. ON DELETE SET NULL: revoking the credential does not orphan or delete the object (the operator
-- re-mints its credential); the object simply loses its recorded owner.
ALTER TABLE k8s_clusters ADD COLUMN managed_by_machine uuid REFERENCES machine_credentials (id) ON DELETE SET NULL;
ALTER TABLE k8s_services ADD COLUMN managed_by_machine uuid REFERENCES machine_credentials (id) ON DELETE SET NULL;
ALTER TABLE policy_rules ADD COLUMN managed_by_machine uuid REFERENCES machine_credentials (id) ON DELETE SET NULL;
