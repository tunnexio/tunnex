DROP INDEX IF EXISTS nodes_enrolled_kind_idx;
ALTER TABLE nodes DROP COLUMN IF EXISTS enrolled_kind;
ALTER TABLE node_join_tokens DROP COLUMN IF EXISTS enrols_kind;
