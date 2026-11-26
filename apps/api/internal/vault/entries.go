package vault

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

const entryColumns = `e.id,e.configured,e.service_id,coalesce(s.name,e.service_name),e.title,e.kind,e.username,e.visibility,
 e.owner_user_id,e.subject_kind,e.subject_id,
 CASE WHEN e.subject_kind='user' THEN coalesce(nullif(su.name,''),su.email::text,'Former user')
 WHEN e.subject_kind='group' THEN coalesce(sg.name,'Former group') ELSE NULL END,
 e.current_version,e.revision,e.created_at,e.updated_at`
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
	err := row.Scan(&v.Id, &v.Configured, &v.ServiceId, &v.ServiceName, &v.Title, &v.Kind, &v.Username, &v.Visibility,
		&v.OwnerUserId, &v.SubjectKind, &v.SubjectId, &v.SubjectName, &v.CurrentVersion, &v.Revision, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		return v, err
	}
	owns := string(v.Visibility) == "personal" && v.OwnerUserId == user
	administers := string(v.Visibility) == "assigned" && a.canAssign
	// can_edit: save a new secret version (recipients included). can_edit_details: title, username,
	// service, recipient — owners of personal entries and Vault administrators only (V2).
	v.CanEdit = true
	v.CanEditDetails = v.Configured && (owns || administers)
	v.CanDelete = owns || administers
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

// listViews are fixed SQL fragments (never caller text) applied on top of visibleEntries (V10).
var listViews = map[string]string{
	"all":      "",
	"personal": ` AND e.visibility='personal'`,
	"shared": ` AND e.visibility='assigned' AND ((e.subject_kind='user' AND e.subject_id=$2) OR (e.subject_kind='group' AND EXISTS(
 SELECT 1 FROM group_members gm WHERE gm.org_id=e.org_id AND gm.group_id=e.subject_id AND gm.user_id=$2)))`,
	"assigned": ` AND e.visibility='assigned'`,
}

// likeContains makes search text literal: %, _ and \ match themselves (V16).
func likeContains(v string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(v) + "%"
}

func (s *Service) List(ctx context.Context, org, user uuid.UUID, limit, offset int32, search string) (api.VaultWorkspace, error) {
	return s.ListView(ctx, org, user, limit, offset, search, "all")
}

func (s *Service) ListView(ctx context.Context, org, user uuid.UUID, limit, offset int32, search, view string) (api.VaultWorkspace, error) {
	out := api.VaultWorkspace{Entries: []api.VaultEntry{}}
	limit, offset, err := pagination(limit, offset)
	if err != nil {
		return out, err
	}
	if view == "" {
		view = "all"
	}
	viewFilter, ok := listViews[view]
	if !ok {
		return out, invalid()
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
	filter := visibleEntries + viewFilter + ` AND ($4='' OR e.title ILIKE $5 ESCAPE '\' OR coalesce(s.name,e.service_name) ILIKE $5 ESCAPE '\' OR e.username ILIKE $5 ESCAPE '\')`
	pattern := likeContains(search)
	err = tx.QueryRow(ctx, "SELECT count(*)"+entryJoins+" WHERE "+filter, org, user, a.canAssign, search, pattern).Scan(&out.Total)
	if err != nil {
		return out, err
	}
	rows, err := tx.Query(ctx, "SELECT "+entryColumns+entryJoins+" WHERE "+filter+" ORDER BY e.updated_at DESC,e.id DESC LIMIT $6 OFFSET $7", org, user, a.canAssign, search, pattern, limit, offset)
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
	if !validText(title, 160, false) || !validText(username, 320, true) || (in.Secret == nil || !validText(*in.Secret, maxSecret, false)) ||
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
	if err = validateTargets(ctx, tx, org, in.ServiceId, in.SubjectId, subjectKind); err != nil {
		return api.VaultEntry{}, err
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
	v, err := readEntry(ctx, tx, org, user, id, a, false)
	if err != nil {
		return v, err
	}
	if err = audit(ctx, tx, org, user, v, "created", 1, nil); err != nil {
		return api.VaultEntry{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return v, err
	}
	return v, nil
}

func validateTargets(ctx context.Context, tx pgx.Tx, org uuid.UUID, serviceID, subjectID *uuid.UUID, subjectKind string) error {
	if serviceID != nil {
		var id uuid.UUID
		err := tx.QueryRow(ctx, `SELECT id FROM vault_services WHERE org_id=$1 AND id=$2 FOR SHARE`, org, *serviceID).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return invalid()
		}
		if err != nil {
			return err
		}
	}
	if subjectKind != "" {
		var id uuid.UUID
		var err error
		if subjectKind == "user" {
			// The same eligibility as begin(): a recipient who could never open the entry is refused (V1).
			var roles []string
			var eligible bool
			err = tx.QueryRow(ctx, `SELECT u.id,coalesce(m.roles,ARRAY[m.role]),(`+eligibleMembership+`) FROM users u JOIN memberships m ON m.user_id=u.id
 WHERE m.org_id=$1 AND m.user_id=$2 FOR SHARE OF m,u`, org, *subjectID).Scan(&id, &roles, &eligible)
			if err == nil && (!eligible || !canUseVault(roles)) {
				return recipientWithoutAccess()
			}
		} else {
			err = tx.QueryRow(ctx, `SELECT id FROM user_groups WHERE org_id=$1 AND id=$2 FOR SHARE`, org, *subjectID).Scan(&id)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return invalid()
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Update rotates: it saves a new secret version. Recipients of an assigned entry may rotate; changing the
// title needs details authority (V2). An omitted username keeps the current one.
func (s *Service) Update(ctx context.Context, org, user, id uuid.UUID, in api.VaultUpdateInput) (api.VaultEntry, error) {
	if in.Secret == nil || !validText(*in.Secret, maxSecret, false) || in.ExpectedVersion < 1 {
		return api.VaultEntry{}, invalid()
	}
	if in.Title != nil && !validText(strings.TrimSpace(*in.Title), 160, false) || in.Username != nil && !validText(*in.Username, 320, true) {
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
	if !v.Configured {
		return api.VaultEntry{}, apierr.New(409, "vault_configuration_required", "Add details to this entry before changing its password")
	}
	title, username := v.Title, v.Username
	if in.Title != nil && strings.TrimSpace(*in.Title) != v.Title {
		if !v.CanEditDetails {
			return api.VaultEntry{}, detailsForbidden()
		}
		title = strings.TrimSpace(*in.Title)
	}
	if in.Username != nil {
		username = *in.Username
	}
	if v.CurrentVersion != in.ExpectedVersion {
		return api.VaultEntry{}, conflict()
	}
	version := v.CurrentVersion + 1
	if err = s.writeVersion(ctx, tx, org, user, id, version, *in.Secret, username); err != nil {
		return api.VaultEntry{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE vault_entries SET title=$3,username=$4,current_version=$5,revision=revision+1 WHERE org_id=$1 AND id=$2`, org, id, title, username, version)
	if err != nil {
		return api.VaultEntry{}, err
	}
	v, err = readEntry(ctx, tx, org, user, id, a, false)
	if err != nil {
		return v, err
	}
	if err = audit(ctx, tx, org, user, v, "updated", version, nil); err != nil {
		return api.VaultEntry{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return v, err
	}
	return v, nil
}

func revisionConflict() error {
	return apierr.New(409, "vault_revision_conflict", "This entry changed. Refresh it before saving")
}

// UpdateDetails changes title, username, service or recipient without a new secret version (V5).
// Personal entries: owner only. Assigned entries: Vault administrators, including reassignment.
// Visibility never changes here.
func (s *Service) UpdateDetails(ctx context.Context, org, user, id uuid.UUID, in api.VaultDetailsInput) (api.VaultEntry, error) {
	if in.ExpectedRevision < 1 || in.Title != nil && !validText(strings.TrimSpace(*in.Title), 160, false) || in.Username != nil && !validText(*in.Username, 320, true) ||
		in.ServiceName != nil && !validText(strings.TrimSpace(*in.ServiceName), 120, false) || in.ServiceId != nil && (*in.ServiceId == uuid.Nil || in.ServiceName != nil) ||
		(in.SubjectId == nil) != (in.SubjectKind == nil) || in.SubjectId != nil && *in.SubjectId == uuid.Nil {
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
	if !v.Configured {
		return api.VaultEntry{}, apierr.New(409, "vault_configuration_required", "Add details to this entry first")
	}
	if !v.CanEditDetails {
		return api.VaultEntry{}, detailsForbidden()
	}
	personal := string(v.Visibility) == "personal"
	if personal && in.SubjectId != nil {
		return api.VaultEntry{}, apierr.BadRequest("vault_visibility_change_unsupported", "A personal credential cannot be shared. Add it again as an assigned credential.")
	}
	if !personal && in.ServiceName != nil {
		return api.VaultEntry{}, invalid() // assigned entries use the catalog
	}
	if v.Revision != in.ExpectedRevision {
		return api.VaultEntry{}, revisionConflict()
	}
	subjectKind := ""
	if in.SubjectKind != nil {
		subjectKind = string(*in.SubjectKind)
		if subjectKind != "user" && subjectKind != "group" {
			return api.VaultEntry{}, invalid()
		}
	}
	if err = validateTargets(ctx, tx, org, in.ServiceId, in.SubjectId, subjectKind); err != nil {
		return api.VaultEntry{}, err
	}
	title, username := v.Title, v.Username
	serviceID, serviceName := v.ServiceId, ""
	if v.ServiceId == nil {
		serviceName = v.ServiceName
	}
	var subject any = nil
	var subjectID *uuid.UUID
	if v.SubjectKind != nil {
		subject, subjectID = string(*v.SubjectKind), v.SubjectId
	}
	fields := []string{}
	if in.Title != nil && strings.TrimSpace(*in.Title) != title {
		title = strings.TrimSpace(*in.Title)
		fields = append(fields, "title")
	}
	if in.Username != nil && *in.Username != username {
		username = *in.Username
		fields = append(fields, "username")
	}
	if in.ServiceId != nil && (v.ServiceId == nil || *v.ServiceId != *in.ServiceId) {
		serviceID, serviceName = in.ServiceId, ""
		fields = append(fields, "service")
	}
	if in.ServiceName != nil && (v.ServiceId != nil || strings.TrimSpace(*in.ServiceName) != v.ServiceName) {
		serviceID, serviceName = nil, strings.TrimSpace(*in.ServiceName)
		fields = append(fields, "service")
	}
	if in.SubjectId != nil && (subjectID == nil || *subjectID != *in.SubjectId || subject != subjectKind) {
		subject, subjectID = subjectKind, in.SubjectId
		fields = append(fields, "recipient")
	}
	if len(fields) == 0 {
		if err = tx.Commit(ctx); err != nil {
			return api.VaultEntry{}, err
		}
		return v, nil
	}
	_, err = tx.Exec(ctx, `UPDATE vault_entries SET title=$3,username=$4,service_id=$5,service_name=$6,subject_kind=$7,subject_id=$8,revision=revision+1
 WHERE org_id=$1 AND id=$2`, org, id, title, username, serviceID, serviceName, subject, subjectID)
	if err != nil {
		return api.VaultEntry{}, err
	}
	before := v
	v, err = readEntry(ctx, tx, org, user, id, a, false)
	if err != nil {
		return api.VaultEntry{}, err
	}
	extra := map[string]any{"fields": fields}
	if !personal && before.SubjectName != nil && fieldsInclude(fields, "recipient") {
		extra["recipient_from"] = *before.SubjectName
	}
	if err = audit(ctx, tx, org, user, v, "details_changed", 0, extra); err != nil {
		return api.VaultEntry{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return api.VaultEntry{}, err
	}
	return v, nil
}

func fieldsInclude(fields []string, want string) bool {
	for _, f := range fields {
		if f == want {
			return true
		}
	}
	return false
}

// QuickRequestRetention bounds the quick-generate idempotency rows (V18). A retry older than this is not a
// real client; the saved passwords themselves are never touched.
const QuickRequestRetention = 30 * 24 * time.Hour

// PruneQuickRequests deletes up to batch quick-request rows older than olderThan.
func (s *Service) PruneQuickRequests(ctx context.Context, olderThan time.Duration, batch int) (int64, error) {
	if s == nil || s.pool == nil || olderThan <= 0 || batch < 1 {
		return 0, nil
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM vault_quick_requests WHERE ctid IN (
 SELECT ctid FROM vault_quick_requests WHERE created_at < now() - make_interval(secs => $1) ORDER BY created_at LIMIT $2)`, olderThan.Seconds(), batch)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
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
	if err = audit(ctx, tx, org, user, v, "deleted", v.CurrentVersion, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
