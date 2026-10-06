-- Keep historical sessions/recordings while permanently retiring a server identity.
ALTER TABLE server_access_servers ADD COLUMN removed_at timestamptz;
