CREATE TABLE saved_ssh_keys (
 id uuid PRIMARY KEY,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
 public_key text NOT NULL CHECK (octet_length(public_key) <= 8192),
 fingerprint text NOT NULL,
 is_default boolean NOT NULL DEFAULT false,
 UNIQUE(user_id, fingerprint)
);
CREATE UNIQUE INDEX saved_ssh_keys_one_default ON saved_ssh_keys(user_id) WHERE is_default;
