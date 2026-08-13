-- 0009 (S3.2) — the node reports its WireGuard public key (generated locally;
-- the private key never leaves the node). The control plane stores pubkeys only.
ALTER TABLE nodes ADD COLUMN wg_public_key text NOT NULL DEFAULT '';
