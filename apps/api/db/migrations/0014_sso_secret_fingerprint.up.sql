-- 0014 sso secret fingerprint (S4.5).
--
-- A KEYED fingerprint (HMAC of the client secret under a master-key subkey; see
-- crypto.Sealer.Fingerprint) stored alongside the sealed secret, so the settings
-- UI can prove "the stored secret is the one you pasted" WITHOUT the plaintext
-- ever leaving the seal. The GET response returns this, never the secret.
-- Default '' covers rows written before this column (re-saving recomputes it).
ALTER TABLE sso_configs ADD COLUMN secret_fingerprint text NOT NULL DEFAULT '';
