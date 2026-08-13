ALTER TABLE node_rekey_challenges DROP COLUMN identifier_kind;
ALTER TABLE node_rekey_challenges DROP COLUMN identifier;
DELETE FROM node_rekey_challenges WHERE cert_serial IS NULL;
ALTER TABLE node_rekey_challenges ALTER COLUMN cert_serial SET NOT NULL;
DROP INDEX IF EXISTS nodes_cert_key_fingerprint_idx;
ALTER TABLE nodes DROP COLUMN cert_key_fingerprint;
