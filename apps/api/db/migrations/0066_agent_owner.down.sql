-- Reverses 0066. Indexes first, then the columns.
DROP INDEX IF EXISTS nodes_owner_user_id_idx;
DROP INDEX IF EXISTS node_join_tokens_issued_by_idx;
ALTER TABLE nodes DROP COLUMN IF EXISTS owner_user_id;
ALTER TABLE node_join_tokens DROP COLUMN IF EXISTS issued_by;
