-- Application authentication policy is live authority, not an immutable draft revision.
ALTER TABLE app_access_applications ADD COLUMN require_mfa boolean NOT NULL DEFAULT false;
