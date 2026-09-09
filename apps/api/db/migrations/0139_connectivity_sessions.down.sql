-- Do not silently discard an active negotiation during rollback.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM connectivity_sessions WHERE NOT revoked AND expires_at > clock_timestamp()) THEN
        RAISE EXCEPTION 'active connectivity sessions exist; close or expire them before rollback';
    END IF;
END $$;
DROP TABLE connectivity_sessions;
DROP TABLE connectivity_profiles;
