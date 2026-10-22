package vault

import (
	"context"
	"crypto/subtle"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

func quickConflict() error {
	return apierr.New(409, "vault_quick_request_conflict", "This quick request cannot be reused. Generate a new password")
}

// QuickCreate persists one candidate without publishing any service or assignment
// metadata. The client may release it to the clipboard only after this commits.
func (s *Service) QuickCreate(ctx context.Context, org, user uuid.UUID, in api.VaultQuickCreateInput) (api.VaultEntry, error) {
	if in.RequestId == uuid.Nil || in.Secret == nil || !validText(*in.Secret, 16384, false) {
		return api.VaultEntry{}, invalid()
	}
	tx, a, err := s.begin(ctx, org, user)
	if err != nil {
		return api.VaultEntry{}, err
	}
	defer tx.Rollback(ctx)
	// Serialize exact request identities, including the initially missing key.
	// Do not row-lock an existing request before its entry: DELETE locks the entry
	// then nulls the request FK, and the opposite order could deadlock with replay.
	key := org.String() + ":" + user.String() + ":" + in.RequestId.String()
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key); err != nil {
		return api.VaultEntry{}, err
	}
	var entryID *uuid.UUID
	err = tx.QueryRow(ctx, `SELECT entry_id FROM vault_quick_requests WHERE org_id=$1 AND owner_user_id=$2 AND request_id=$3`, org, user, in.RequestId).Scan(&entryID)
	if err == nil {
		if entryID == nil {
			return api.VaultEntry{}, quickConflict()
		}
		entry, e := readEntry(ctx, tx, org, user, *entryID, a, false)
		if e != nil {
			return api.VaultEntry{}, e
		}
		if entry.OwnerUserId != user {
			return api.VaultEntry{}, quickConflict()
		}
		original, e := s.versionValue(ctx, tx, org, *entryID, 1)
		if e != nil {
			return api.VaultEntry{}, e
		}
		if subtle.ConstantTimeCompare([]byte(original.Value), []byte(*in.Secret)) != 1 {
			return api.VaultEntry{}, quickConflict()
		}
		if e = tx.Commit(ctx); e != nil {
			return api.VaultEntry{}, e
		}
		return entry, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return api.VaultEntry{}, err
	}
	id := uuid.New()
	_, err = tx.Exec(ctx, `INSERT INTO vault_entries(id,org_id,title,kind,visibility,owner_user_id,current_version,configured)
 VALUES($1,$2,'','password','personal',$3,1,false)`, id, org, user)
	if err != nil {
		return api.VaultEntry{}, err
	}
	if err = s.writeVersion(ctx, tx, org, user, id, 1, *in.Secret, ""); err != nil {
		return api.VaultEntry{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO vault_quick_requests(org_id,owner_user_id,request_id,entry_id) VALUES($1,$2,$3,$4)`, org, user, in.RequestId, id)
	if err != nil {
		return api.VaultEntry{}, err
	}
	if err = audit(ctx, tx, org, user, id, "quick_created", 1); err != nil {
		return api.VaultEntry{}, err
	}
	entry, err := readEntry(ctx, tx, org, user, id, a, false)
	if err != nil {
		return api.VaultEntry{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return api.VaultEntry{}, err
	}
	return entry, nil
}

// Configure is the single creator-owned transition from an unconfigured password
// to normal ledger metadata. It never accepts a replacement secret or kind.
func (s *Service) Configure(ctx context.Context, org, user, id uuid.UUID, in api.VaultConfigureInput) (api.VaultEntry, error) {
	if in.ExpectedVersion < 1 {
		return api.VaultEntry{}, invalid()
	}
	tx, a, err := s.begin(ctx, org, user)
	if err != nil {
		return api.VaultEntry{}, err
	}
	defer tx.Rollback(ctx)
	entry, err := readEntry(ctx, tx, org, user, id, a, true)
	if err != nil {
		return api.VaultEntry{}, err
	}
	// Creator ownership is checked even if the caller can administer assignments.
	if entry.OwnerUserId != user {
		return api.VaultEntry{}, missing()
	}
	if entry.Configured {
		return api.VaultEntry{}, apierr.New(409, "vault_already_configured", "This entry is already configured")
	}
	if entry.CurrentVersion != in.ExpectedVersion {
		return api.VaultEntry{}, conflict()
	}
	if string(in.Visibility) == "assigned" && !a.canAssign {
		return api.VaultEntry{}, denied()
	}
	original, err := s.versionValue(ctx, tx, org, id, entry.CurrentVersion)
	if err != nil {
		return api.VaultEntry{}, err
	}
	// Reuse the existing full-entry metadata validator with the actual stored
	// password, never a synthetic password or placeholder service/catalog record.
	metadata := api.VaultCreateInput{Title: in.Title, Kind: api.VaultCreateInputKind(entry.Kind), Secret: &original.Value,
		Username: in.Username, Visibility: api.VaultCreateInputVisibility(in.Visibility), ServiceId: in.ServiceId, ServiceName: in.ServiceName, SubjectId: in.SubjectId}
	if in.SubjectKind != nil {
		kind := api.VaultCreateInputSubjectKind(*in.SubjectKind)
		metadata.SubjectKind = &kind
	}
	title, username, serviceName, subjectKind, err := createFields(metadata)
	if err != nil {
		return api.VaultEntry{}, err
	}
	if err = validateTargets(ctx, tx, org, in.ServiceId, in.SubjectId, subjectKind); err != nil {
		return api.VaultEntry{}, err
	}
	version := entry.CurrentVersion + 1
	if err = s.writeVersion(ctx, tx, org, user, id, version, original.Value, username); err != nil {
		return api.VaultEntry{}, err
	}
	var subject any
	if subjectKind != "" {
		subject = subjectKind
	}
	_, err = tx.Exec(ctx, `UPDATE vault_entries SET configured=true,title=$3,username=$4,service_id=$5,service_name=$6,
 visibility=$7,subject_kind=$8,subject_id=$9,current_version=$10 WHERE org_id=$1 AND id=$2`,
		org, id, title, username, in.ServiceId, serviceName, string(in.Visibility), subject, in.SubjectId, version)
	if err != nil {
		return api.VaultEntry{}, err
	}
	if err = audit(ctx, tx, org, user, id, "configured", version); err != nil {
		return api.VaultEntry{}, err
	}
	entry, err = readEntry(ctx, tx, org, user, id, a, false)
	if err != nil {
		return api.VaultEntry{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return api.VaultEntry{}, err
	}
	return entry, nil
}
