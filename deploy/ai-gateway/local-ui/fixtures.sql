-- Local AI UI fixtures extend only the stable development organization.
-- Provider secrets, keys, grants and usage are created through seed.py and the
-- actual API/engine reconciliation paths rather than asserted in SQL.
BEGIN;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM organizations WHERE id = '01900000-0000-7000-8000-000000000001' AND name = 'Demo Organization' AND slug = 'demo') THEN
    RAISE EXCEPTION 'The expected local demo organization is missing';
  END IF;
  IF EXISTS (SELECT 1 FROM user_groups WHERE id = '01900000-0000-7000-8000-0000000a00f1' AND org_id <> '01900000-0000-7000-8000-000000000001') THEN
    RAISE EXCEPTION 'Local AI fixture group belongs to another organization';
  END IF;
END $$;
INSERT INTO user_groups (id, org_id, name, description, origin, created_at, updated_at)
VALUES ('01900000-0000-7000-8000-0000000a00f1', '01900000-0000-7000-8000-000000000001',
        'AI fixture reviewers', 'Local simulated AI models for UI review. No external AI calls.', 'manual', now(), now())
ON CONFLICT (id) DO NOTHING;
INSERT INTO group_members (org_id, group_id, user_id, created_at)
VALUES
 ('01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-0000000a00f1', '01900000-0000-7000-8000-000000000002', now()),
 ('01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-0000000a00f1', '01900000-0000-7000-8000-000000000003', now())
ON CONFLICT (group_id, user_id) DO NOTHING;
COMMIT;
