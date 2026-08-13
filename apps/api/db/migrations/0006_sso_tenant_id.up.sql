-- 0006 (S2.4) — Microsoft Entra pins the org's tenant. Nullable: only used by
-- the microsoft provider; google leaves it null.
ALTER TABLE sso_configs ADD COLUMN tenant_id text;
