CREATE TABLE app_access_grants (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL,
 app_id uuid NOT NULL,
 subject_kind text NOT NULL CHECK(subject_kind IN ('user','group')),
 subject_id uuid NOT NULL,
 subject_label text NOT NULL,
 user_id uuid,
 group_id uuid,
 enabled boolean NOT NULL DEFAULT true,
 starts_at timestamptz,
 expires_at timestamptz,
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 revoked_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(org_id,app_id) REFERENCES app_access_applications(org_id,id) ON DELETE CASCADE,
 FOREIGN KEY(org_id,user_id) REFERENCES memberships(org_id,user_id) ON DELETE SET NULL(user_id),
 FOREIGN KEY(group_id,org_id) REFERENCES user_groups(id,org_id) ON DELETE SET NULL(group_id),
 CHECK(starts_at IS NULL OR expires_at IS NULL OR starts_at<expires_at),
 CHECK((subject_kind='user' AND group_id IS NULL AND (user_id IS NOT NULL AND user_id=subject_id OR user_id IS NULL AND revoked_at IS NOT NULL)) OR (subject_kind='group' AND user_id IS NULL AND (group_id IS NOT NULL AND group_id=subject_id OR group_id IS NULL AND revoked_at IS NOT NULL)))
);
CREATE UNIQUE INDEX app_access_grants_subject_current ON app_access_grants(org_id,app_id,subject_kind,subject_id) WHERE revoked_at IS NULL;
CREATE INDEX app_access_grants_inventory ON app_access_grants(org_id,created_at,id);
-- Directory deletion preserves the declared subject identity and retires its
-- grant in the SAME transaction, so re-creating membership cannot revive it.
CREATE FUNCTION app_access_grant_subject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.org_id<>OLD.org_id OR NEW.app_id<>OLD.app_id OR NEW.subject_kind<>OLD.subject_kind OR NEW.subject_id<>OLD.subject_id THEN RAISE EXCEPTION 'App Access grant subject is immutable' USING ERRCODE='23514'; END IF;
 IF (OLD.user_id IS NOT NULL AND NEW.user_id IS NULL) OR (OLD.group_id IS NOT NULL AND NEW.group_id IS NULL) THEN
  NEW.enabled=false; NEW.revoked_at=coalesce(OLD.revoked_at,now()); NEW.version=OLD.version+1; NEW.updated_at=now();
  INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata) VALUES(OLD.org_id,'app-access-subject-removal','app_access.grant_subject_removed','app_access',OLD.id::text,jsonb_build_object('version',NEW.version,'subject_kind',OLD.subject_kind));
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER app_access_grant_subject_change BEFORE UPDATE ON app_access_grants FOR EACH ROW EXECUTE FUNCTION app_access_grant_subject_change();
