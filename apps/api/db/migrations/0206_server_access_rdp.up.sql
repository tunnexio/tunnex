ALTER TABLE server_access_servers ADD COLUMN os text NOT NULL DEFAULT 'linux' CHECK (os IN ('linux','windows')), ADD COLUMN rdp_domain text NOT NULL DEFAULT '';
