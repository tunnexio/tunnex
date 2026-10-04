ALTER TABLE app_access_applications
 ADD COLUMN catalog_visible boolean NOT NULL DEFAULT false,
 ADD COLUMN app_admin_user_id uuid,
 ADD CONSTRAINT app_access_admin_membership_fk FOREIGN KEY(org_id,app_admin_user_id)
 REFERENCES memberships(org_id,user_id) ON DELETE SET NULL(app_admin_user_id);

-- Directory removal detaches the administrator without losing the app's queue.
CREATE FUNCTION app_access_admin_detached() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.app_admin_user_id IS NOT NULL AND NEW.app_admin_user_id IS NULL AND NEW.version=OLD.version THEN
  NEW.version=OLD.version+1; NEW.updated_at=now();
  INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata)
  VALUES(OLD.org_id,'app-access-admin-removal','app_access.admin_detached','app_access',OLD.id::text,jsonb_build_object('version',NEW.version));
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER app_access_admin_detached BEFORE UPDATE ON app_access_applications
 FOR EACH ROW EXECUTE FUNCTION app_access_admin_detached();

ALTER TABLE app_access_grants ADD CONSTRAINT app_access_grants_request_binding UNIQUE(org_id,app_id,id);

CREATE TABLE app_access_requests (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL,
 app_id uuid NOT NULL,
 app_name text NOT NULL,
 requester_user_id uuid NOT NULL,
 requester_membership_user_id uuid,
 requester_name text NOT NULL,
 requester_email text NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
 reason text NOT NULL DEFAULT '' CHECK(length(reason)<=1000),
 decision_reason text NOT NULL DEFAULT '' CHECK(length(decision_reason)<=1000),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 grant_id uuid,
 decided_by uuid,
 created_at timestamptz NOT NULL DEFAULT now(),
 decided_at timestamptz,
 FOREIGN KEY(org_id,app_id) REFERENCES app_access_applications(org_id,id) ON DELETE CASCADE,
 FOREIGN KEY(org_id,app_id,grant_id) REFERENCES app_access_grants(org_id,app_id,id) ON DELETE SET NULL(grant_id),
 FOREIGN KEY(org_id,requester_membership_user_id) REFERENCES memberships(org_id,user_id) ON DELETE SET NULL(requester_membership_user_id),
 CHECK(requester_membership_user_id IS NULL OR requester_membership_user_id=requester_user_id),
 CHECK((status='pending' AND decided_at IS NULL AND decided_by IS NULL) OR (status<>'pending' AND decided_at IS NOT NULL AND decided_by IS NOT NULL))
);
CREATE UNIQUE INDEX app_access_requests_one_pending ON app_access_requests(org_id,app_id,requester_user_id) WHERE status='pending';
CREATE INDEX app_access_requests_queue ON app_access_requests(org_id,status,created_at,id);
CREATE INDEX app_access_requests_own ON app_access_requests(org_id,requester_user_id,created_at DESC,id);
