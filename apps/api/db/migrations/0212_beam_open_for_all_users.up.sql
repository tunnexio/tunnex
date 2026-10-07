-- Existing organizations retain their explicit publisher/reviewer allowlists.
ALTER TABLE beam_policies ADD COLUMN open_for_all_users boolean NOT NULL DEFAULT false;
