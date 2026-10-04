-- Additive: legacy revisions keep their content and digest; old writers default
-- to no uploaded icon. Images are application metadata, never proxy authority.
ALTER TABLE app_access_revisions
 ADD COLUMN icon_data_url text NOT NULL DEFAULT ''
 CHECK (length(icon_data_url) <= 87406 AND
        (icon_data_url = '' OR icon_data_url ~ '^data:image/png;base64,[A-Za-z0-9+/]+={0,2}$'));
