package vault

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
)

const entryColumns = `e.id,e.service_id,coalesce(s.name,e.service_name),e.title,e.kind,e.username,e.visibility,
 e.owner_user_id,e.subject_kind,e.subject_id,
 CASE WHEN e.subject_kind='user' THEN coalesce(nullif(su.name,''),su.email::text,'Former user')
 WHEN e.subject_kind='group' THEN coalesce(sg.name,'Former group') ELSE NULL END,
 e.current_version,e.created_at,e.updated_at`
const entryJoins = ` FROM vault_entries e
 LEFT JOIN vault_services s ON s.org_id=e.org_id AND s.id=e.service_id
 LEFT JOIN users su ON e.subject_kind='user' AND su.id=e.subject_id
 LEFT JOIN user_groups sg ON e.subject_kind='group' AND sg.org_id=e.org_id AND sg.id=e.subject_id `
const visibleEntries = `e.org_id=$1 AND ((e.visibility='personal' AND e.owner_user_id=$2) OR
 (e.visibility='assigned' AND ($3 OR (e.subject_kind='user' AND e.subject_id=$2) OR
 (e.subject_kind='group' AND EXISTS(SELECT 1 FROM group_members gm JOIN user_groups g ON g.id=gm.group_id AND g.org_id=gm.org_id
 WHERE gm.org_id=e.org_id AND gm.group_id=e.subject_id AND gm.user_id=$2)))))`

type rowScanner interface{ Scan(...any) error }

func scanEntry(row rowScanner, user uuid.UUID, a authority) (api.VaultEntry, error) {
	var v api.VaultEntry
	err := row.Scan(&v.Id, &v.ServiceId, &v.ServiceName, &v.Title, &v.Kind, &v.Username, &v.Visibility,
		&v.OwnerUserId, &v.SubjectKind, &v.SubjectId, &v.SubjectName, &v.CurrentVersion, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		return v, err
	}
	v.CanEdit = true
	v.CanDelete = string(v.Visibility) == "personal" && v.OwnerUserId == user || string(v.Visibility) == "assigned" && a.canAssign
	return v, nil
}

// A row lock keeps authority attached to the exact entry during reveal/update.
// For group readers a share lock also serializes the read with group removal.
func readEntry(ctx context.Context, tx pgx.Tx, org, user, id uuid.UUID, a authority, write bool) (api.VaultEntry, error) {
	lock := " FOR SHARE OF e"
	if write {
		lock = " FOR UPDATE OF e"
	}
	v, err := scanEntry(tx.QueryRow(ctx, "SELECT "+entryColumns+entryJoins+" WHERE e.org_id=$1 AND e.id=$2"+lock, org, id), user, a)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, missing()
	}
	if err != nil {
		return v, err
	}
	if string(v.Visibility) == "personal" {
		if v.OwnerUserId != user {
			return api.VaultEntry{}, missing()
		}
		return v, nil
	}
	if a.canAssign {
		return v, nil
	}
	if v.SubjectKind == nil || v.SubjectId == nil {
		return api.VaultEntry{}, missing()
	}
	switch string(*v.SubjectKind) {
	case "user":
		if *v.SubjectId == user {
			return v, nil
		}
	case "group":
		var found uuid.UUID
		err = tx.QueryRow(ctx, `SELECT gm.user_id FROM group_members gm JOIN user_groups g ON g.id=gm.group_id AND g.org_id=gm.org_id
 WHERE gm.org_id=$1 AND gm.group_id=$2 AND gm.user_id=$3 FOR SHARE OF gm,g`, org, *v.SubjectId, user).Scan(&found)
		if err == nil {
			return v, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return api.VaultEntry{}, err
		}
	}
	return api.VaultEntry{}, missing()
}

func pagination(limit, offset int32) (int32, int32, error) {
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 || offset < 0 || offset > 100000 {
		return 0, 0, invalid()
	}
	return limit, offset, nil
}

func (s *Service) List(ctx context.Context, org, user uuid.UUID, limit, offset int32, search string) (api.VaultWorkspace, error) {
	out := api.VaultWorkspace{Entries: []api.VaultEntry{}}
	limit, offset, err := pagination(limit, offset)
	if err != nil {
		return out, err
	}
	search = strings.TrimSpace(search)
	if !validText(search, 100, true) {
		return out, invalid()
	}
	tx, a, err := s.begin(ctx, org, user)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	out.CanAssign = a.canAssign
	filter := visibleEntries + ` AND ($4='' OR e.title ILIKE '%'||$4||'%' OR coalesce(s.name,e.service_name) ILIKE '%'||$4||'%' OR e.username ILIKE '%'||$4||'%')`
	err = tx.QueryRow(ctx, "SELECT count(*)"+entryJoins+" WHERE "+filter, org, user, a.canAssign, search).Scan(&out.Total)
	if err != nil {
		return out, err
	}
	rows, err := tx.Query(ctx, "SELECT "+entryColumns+entryJoins+" WHERE "+filter+" ORDER BY e.updated_at DESC,e.id DESC LIMIT $5 OFFSET $6", org, user, a.canAssign, search, limit, offset)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		v, e := scanEntry(rows, user, a)
		if e != nil {
			rows.Close()
			return out, e
		}
		out.Entries = append(out.Entries, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if err = tx.Commit(ctx); err != nil {
		return out, err
	}
	return out, nil
}

func createFields(in api.VaultCreateInput) (title, username, serviceName, subjectKind string, err error) {
	title = strings.TrimSpace(in.Title)
	if in.Username != nil {
		username = *in.Username
	}
	if in.ServiceName != nil {
		serviceName = strings.TrimSpace(*in.ServiceName)
	}
	if in.SubjectKind != nil {
		subjectKind = string(*in.SubjectKind)
	}
	if !validText(title, 160, false) || !validText(username, 320, true) || (in.Secret == nil || !validText(*in.Secret, 16384, false)) ||
		!validText(serviceName, 120, true) || (string(in.Kind) != "password" && string(in.Kind) != "api_key") ||
		(string(in.Visibility) != "personal" && string(in.Visibility) != "assigned") {
		err = invalid()
		return
	}
	if in.ServiceId != nil && *in.ServiceId == uuid.Nil || in.ServiceId != nil && serviceName != "" || in.ServiceId == nil && serviceName == "" {
		err = invalid()
		return
	}
	if string(in.Visibility) == "personal" {
		if in.SubjectKind != nil || in.SubjectId != nil {
			err = invalid()
		}
		return
	}
	if in.ServiceId == nil || in.SubjectId == nil || *in.SubjectId == uuid.Nil || (subjectKind != "user" && subjectKind != "group") {
		err = invalid()
	}
	return
}

func (s *Service) Create(ctx context.Context, org, user uuid.UUID, in api.VaultCreateInput) (api.VaultEntry, error) {
	title, username, serviceName, subjectKind, err := createFields(in)
	if err != nil {
		return api.VaultEntry{}, err
	}
	tx, a, err := s.begin(ctx, org, user)
	if err != nil {
		return api.VaultEntry{}, err
	}
	defer tx.Rollback(ctx)
	if string(in.Visibility) == "assigned" && !a.canAssign {
		return api.VaultEntry{}, denied()
	}
	if in.ServiceId != nil {
		var id uuid.UUID
		err = tx.QueryRow(ctx, `SELECT id FROM vault_services WHERE org_id=$1 AND id=$2 FOR SHARE`, org, *in.ServiceId).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return api.VaultEntry{}, invalid()
		}
		if err != nil {
			return api.VaultEntry{}, err
		}
	}
	if string(in.Visibility) == "assigned" {
		var id uuid.UUID
		if subjectKind == "user" {
			err = tx.QueryRow(ctx, `SELECT u.id FROM users u JOIN memberships m ON m.user_id=u.id
 WHERE m.org_id=$1 AND m.user_id=$2 AND m.access_revoked_at IS NULL AND u.status='active' AND u.deleted_at IS NULL FOR SHARE OF m,u`, org, *in.SubjectId).Scan(&id)
		} else {
			err = tx.QueryRow(ctx, `SELECT id FROM user_groups WHERE org_id=$1 AND id=$2 FOR SHARE`, org, *in.SubjectId).Scan(&id)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return api.VaultEntry{}, invalid()
		}
		if err != nil {
			return api.VaultEntry{}, err
		}
	}
	id := uuid.New()
	var subject any
	if subjectKind != "" {
		subject = subjectKind
	}
	_, err = tx.Exec(ctx, `INSERT INTO vault_entries(id,org_id,service_id,service_name,title,kind,username,visibility,owner_user_id,subject_kind,subject_id,current_version)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1)`, id, org, in.ServiceId, serviceName, title, string(in.Kind), username, string(in.Visibility), user, subject, in.SubjectId)
	if err != nil {
		return api.VaultEntry{}, err
	}
	if err = s.writeVersion(ctx, tx, org, user, id, 1, *in.Secret, username); err != nil {
		return api.VaultEntry{}, err
	}
	if err = audit(ctx, tx, org, user, id, "created", 1); err != nil {
		return api.VaultEntry{}, err
	}
	v, err := readEntry(ctx, tx, org, user, id, a, false)
	if err != nil {
		return v, err
	}
	if err = tx.Commit(ctx); err != nil {
		return v, err
	}
	return v, nil
}

func (s *Service) Update(ctx context.Context, org, user, id uuid.UUID, in api.VaultUpdateInput) (api.VaultEntry, error) {
	title := strings.TrimSpace(in.Title)
	username := ""
	if in.Username != nil {
		username = *in.Username
	}
	if !validText(title, 160, false) || !validText(username, 320, true) || (in.Secret == nil || !validText(*in.Secret, 16384, false)) || in.ExpectedVersion < 1 {
		return api.VaultEntry{}, invalid()
	}
	tx, a, err := s.begin(ctx, org, user)
	if err != nil {
		return api.VaultEntry{}, err
	}
	defer tx.Rollback(ctx)
	v, err := readEntry(ctx, tx, org, user, id, a, true)
	if err != nil {
		return api.VaultEntry{}, err
	}
	if v.CurrentVersion != in.ExpectedVersion {
		return api.VaultEntry{}, conflict()
	}
	version := v.CurrentVersion + 1
	if err = s.writeVersion(ctx, tx, org, user, id, version, *in.Secret, username); err != nil {
		return api.VaultEntry{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE vault_entries SET title=$3,username=$4,current_version=$5 WHERE org_id=$1 AND id=$2`, org, id, title, username, version)
	if err != nil {
		return api.VaultEntry{}, err
	}
	if err = audit(ctx, tx, org, user, id, "updated", version); err != nil {
		return api.VaultEntry{}, err
	}
	v, err = readEntry(ctx, tx, org, user, id, a, false)
	if err != nil {
		return v, err
	}
	if err = tx.Commit(ctx); err != nil {
		return v, err
	}
	return v, nil
}

func (s *Service) Delete(ctx context.Context, org, user, id uuid.UUID, expectedVersion int) error {
	if expectedVersion < 1 {
		return invalid()
	}
	tx, a, err := s.begin(ctx, org, user)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	v, err := readEntry(ctx, tx, org, user, id, a, true)
	if err != nil {
		return err
	}
	if !v.CanDelete {
		return denied()
	}
	if v.CurrentVersion != expectedVersion {
		return conflict()
	}
	if _, err = tx.Exec(ctx, `DELETE FROM vault_entries WHERE org_id=$1 AND id=$2`, org, id); err != nil {
		return err
	}
	if err = audit(ctx, tx, org, user, id, "deleted", v.CurrentVersion); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
