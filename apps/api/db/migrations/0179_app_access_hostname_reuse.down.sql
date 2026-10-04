-- Acquire the tenant root before child DDL, matching application mutation order.
LOCK TABLE organizations IN EXCLUSIVE MODE;

-- Restoring the old global uniqueness is impossible after hostname reuse without
-- discarding history. Refuse downgrade; an operator must retain schema 179.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM app_access_hostnames GROUP BY hostname HAVING count(*)>1)
 OR EXISTS(SELECT 1 FROM app_access_serving_publications GROUP BY hostname HAVING count(*)>1) THEN
  RAISE EXCEPTION 'Cannot downgrade App Access hostname reuse while historical duplicate hostnames exist';
 END IF;
END $$;
DROP TRIGGER app_access_archive_release_hostnames ON app_access_applications;
DROP FUNCTION app_access_archive_release_hostnames();
DROP TRIGGER app_access_hostname_history_guard ON app_access_hostnames;
DROP FUNCTION app_access_hostname_history_guard();
DROP INDEX app_access_publication_live_hostname;
ALTER TABLE app_access_serving_publications ADD CONSTRAINT app_access_serving_publications_hostname_key UNIQUE(hostname);
DROP INDEX app_access_hostname_live_claim;
ALTER TABLE app_access_hostnames ADD CONSTRAINT app_access_hostnames_pkey PRIMARY KEY(hostname);
ALTER TABLE app_access_hostnames DROP COLUMN released_at;
