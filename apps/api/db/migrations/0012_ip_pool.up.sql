-- 0012 org IP pool + org-wide address uniqueness (S3.5).
--
-- The tunnel address allocation lives ON the device (devices.assigned_ip) — a
-- device IS an allocation. This migration makes the pool explicit (per-org CIDR)
-- and moves the uniqueness scope from per-NODE to per-ORG: a flat org pool where
-- an address is unique across all of the org's nodes (site-to-site, EPIC 8,
-- needs org-wide-unique addresses). The existing assigned_ip values are already
-- tracked on their rows, so no data moves — only the uniqueness scope tightens.
-- (Interim per-node allocations on a single node don't overlap, so the new index
-- builds cleanly; a pre-existing cross-node collision would have to be resolved
-- before applying, by design — the allocator must never double-assign.)

ALTER TABLE organizations ADD COLUMN pool_cidr text NOT NULL DEFAULT '10.99.0.0/24';

DROP INDEX IF EXISTS devices_node_ip_key;
CREATE UNIQUE INDEX devices_org_ip_key ON devices (org_id, assigned_ip)
    WHERE assigned_ip IS NOT NULL AND status = 'active' AND deleted_at IS NULL;
