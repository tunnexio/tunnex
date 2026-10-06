ALTER TABLE server_access_settings ADD COLUMN mfa_freshness_seconds integer NOT NULL DEFAULT 900 CHECK(mfa_freshness_seconds BETWEEN 60 AND 900);
