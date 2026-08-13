-- ⛔ THE FIRST DEPLOYMENT-SCOPED AUTHORITY IN THIS PRODUCT, AND IT IS DELIBERATELY ONE BOOLEAN.
--
-- Every authority the identity model carries today is org-keyed by construction: `Principal.Roles` is
-- `map[orgID]role`, and `rbac.Can(role, perm)` takes a role that only exists INSIDE an org. So there was no
-- way to express "may create an organization" — because a permission granted in org A cannot license an act
-- that creates org B. `PermOrgManage` does not fit, and stretching it would have lied about what it means.
--
-- ⛔ NOT A DEPLOYMENT-LEVEL ROLE SYSTEM (founder-ruled). A second role axis is a blast radius: every
-- existing check would have to decide which axis it consults, and this story needs exactly one question
-- answered. A boolean answers it and cannot grow teeth by accident.
--
-- ⚠ DEFAULT FALSE, AND THAT IS THE WHOLE SECURITY PROPERTY. `/api/v1/auth/signup` is `security: []` — open
-- to anyone who can reach the deployment. Every account it mints arrives without this capability, so a
-- stranger can hold an account and never an organization.
ALTER TABLE users ADD COLUMN can_create_orgs boolean NOT NULL DEFAULT false;

-- ⭐ THE EXISTING OWNER OF THE FIRST ORGANIZATION KEEPS WORKING. A deployment upgrading into this migration
-- must not lose the ability to administer itself: whoever already owns an organization here was admitted
-- before this capability existed, and revoking it retroactively would strand a live deployment with nobody
-- able to create anything. ⚠ Grandfathering OWNERS ONLY — members and admins get nothing.
UPDATE users SET can_create_orgs = true
WHERE id IN (SELECT user_id FROM memberships WHERE role = 'owner');
