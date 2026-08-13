DROP TABLE idp_sync_configs;

ALTER TABLE group_members DROP COLUMN origin;

DROP INDEX user_groups_idp_unique;
ALTER TABLE user_groups
    DROP CONSTRAINT user_groups_origin_shape,
    DROP COLUMN origin,
    DROP COLUMN idp_provider,
    DROP COLUMN idp_group_id;
