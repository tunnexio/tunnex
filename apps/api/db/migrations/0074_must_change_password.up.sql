-- ⛔ THE FIRST-LOGIN PASSWORD CHANGE, AS A COLUMN RATHER THAN A CONVENTION.
--
-- The CP admin's initial password is PRINTED TO THE LOGS at first start. Logs are read by anyone with
-- docker access, are shipped to aggregators, and are not a secret store — so that credential must be
-- treated as compromised from the moment it is useful, and the only safe lifetime is "until first login".
--
-- ⚠ A FLAG, NOT A TIMESTAMP COMPARISON. "password_changed_at IS NULL" would read as unchanged for every
-- account created before this column existed, and an invited user who sets their own password at accept
-- time has genuinely never needed a change. The flag says exactly one thing and says it explicitly.
ALTER TABLE users ADD COLUMN must_change_password boolean NOT NULL DEFAULT false;
