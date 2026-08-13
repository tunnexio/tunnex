-- 0003 — slugs are permanently claimed (S1.2 decision).
--
-- 0002 made the slug unique only among LIVE orgs (partial index), which would
-- let a soft-deleted org's slug be reused. We block reuse instead:
--   * restore-safety: an org can be un-soft-deleted without a slug collision;
--   * no reference confusion: a slug always maps to at most one org, ever.
-- Durable references (agent enrollment, APIs) use the org UUID, never the slug;
-- the slug is a human-facing, immutable-after-creation label.
DROP INDEX IF EXISTS organizations_slug_key;
CREATE UNIQUE INDEX organizations_slug_key ON organizations (slug);
