ALTER TABLE connectivity_profiles ADD COLUMN relay_url text NOT NULL DEFAULT '';
ALTER TABLE connectivity_profiles ADD COLUMN secret_sealed text;
ALTER TABLE connectivity_profiles ADD COLUMN revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0);
