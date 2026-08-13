-- F3: per-rule enable/disable toggle. A disabled ALLOW-rule is compiled to nothing (the compiler skips
-- it), so under default-deny it REMOVES its permission — "as if the rule weren't there", not a deny-rule.
-- Default false = every existing rule stays enabled. The compiler input (ListActivePolicyRulesForOrg)
-- passes disabled rows THROUGH to the compiler, which owns the skip (the unit-tested Compile predicate);
-- disabling changes the compiled artifact's CONTENT → in-hash → an ordinary desync-free push.
ALTER TABLE policy_rules ADD COLUMN disabled boolean NOT NULL DEFAULT false;
