package appaccess

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/pgerr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type GrantListFilter struct {
	View   string
	Search string
	Status string
}

func NormalizeGrantListFilter(filter GrantListFilter) (GrantListFilter, error) {
	filter.Search = strings.TrimSpace(filter.Search)
	if !utf8.ValidString(filter.Search) || utf8.RuneCountInString(filter.Search) > 200 {
		return filter, apierr.BadRequest("invalid_grant_filter", "search must contain at most 200 characters")
	}
	switch filter.Status {
	case "", "scheduled", "active", "expired", "disabled", "revoked", "subject_unavailable":
	default:
		return filter, apierr.BadRequest("invalid_grant_filter", "invalid grant status")
	}
	switch filter.View {
	case "":
	case "current":
		if filter.Status == "revoked" || filter.Status == "expired" {
			return filter, apierr.BadRequest("invalid_grant_filter", "history status requires the history view")
		}
	case "history":
		if filter.Status != "" && filter.Status != "revoked" && filter.Status != "expired" {
			return filter, apierr.BadRequest("invalid_grant_filter", "current status requires the current view")
		}
	default:
		return filter, apierr.BadRequest("invalid_grant_filter", "invalid grant view")
	}
	return filter, nil
}

type GrantInput struct {
	AppID       uuid.UUID
	SubjectKind string
	SubjectID   uuid.UUID
	Enabled     bool
	StartsAt    *time.Time
	ExpiresAt   *time.Time
}
type GrantUpdate struct {
	Enabled   bool
	StartsAt  *time.Time
	ExpiresAt *time.Time
}
type Grant struct {
	ID           uuid.UUID
	OrgID        uuid.UUID
	AppID        uuid.UUID
	AppLabel     string
	SubjectKind  string
	SubjectID    uuid.UUID
	SubjectLabel string
	Enabled      bool
	StartsAt     *time.Time
	ExpiresAt    *time.Time
	Version      int64
	RevokedAt    *time.Time
	Status       string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
type Preview struct {
	EvaluatedAt      time.Time
	GrantMatch       bool
	MatchingGrantIDs []uuid.UUID
	AccessAllowed    bool
	DenyReason       string
	NextExpiryAt     *time.Time
}
type GrantImpact struct {
	MatchingUserCount          int64
	UsersLosingGrantMatchCount int64
	EvaluatedAt                time.Time
	GrantVersion               int64
	SessionImpactAvailable     bool
}

func (s *Service) now() time.Time {
	if s.config.Now != nil {
		return s.config.Now().UTC()
	}
	return time.Now().UTC()
}
func timestamp(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: t.UTC().Truncate(time.Microsecond), Valid: true}
}
func timePointer(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time.UTC()
	return &v
}
func nullableID(id *uuid.UUID) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *id, Valid: true}
}
func validWindow(start, end *time.Time) error {
	for _, t := range []*time.Time{start, end} {
		if t != nil && (t.IsZero() || t.Year() < 1 || t.Year() > 9999) {
			return apierr.BadRequest("invalid_grant_window", "use finite timestamps")
		}
	}
	if start != nil && end != nil && !start.Truncate(time.Microsecond).Before(end.Truncate(time.Microsecond)) {
		return apierr.BadRequest("invalid_grant_window", "expiry must be after start")
	}
	return nil
}
func sameTime(a *time.Time, b pgtype.Timestamptz) bool {
	return a == nil && !b.Valid || a != nil && b.Valid && a.Equal(b.Time)
}
func lockGrantOrg(ctx context.Context, q *sqlc.Queries, org uuid.UUID) error {
	_, e := q.LockActiveAppAccessOrganization(ctx, org)
	if errors.Is(e, pgx.ErrNoRows) {
		return notFound()
	}
	return e
}
func (s *Service) requireGrantFeature(ctx context.Context, q *sqlc.Queries, org uuid.UUID, entitled bool) error {
	if !entitled {
		return apierr.Forbidden("feature_unavailable", "App Access entitlement required")
	}
	enabled, e := q.LockAppAccessSettings(ctx, org)
	if errors.Is(e, pgx.ErrNoRows) || e == nil && !enabled {
		return apierr.Forbidden("app_access_disabled", "enable App Access for this organization first")
	}
	if e != nil {
		return e
	}
	if !s.domainConfiguredWithQueries(ctx, q) {
		return apierr.Conflict("app_domain_unavailable", "configure a separate App Access base domain first")
	}
	return nil
}
func lockSubject(ctx context.Context, q *sqlc.Queries, org, id uuid.UUID, kind string) (string, error) {
	if kind == "user" {
		u, e := q.LockAppAccessUserSubject(ctx, sqlc.LockAppAccessUserSubjectParams{OrgID: org, UserID: id})
		if errors.Is(e, pgx.ErrNoRows) {
			return "", notFound()
		}
		if u.Name != "" {
			return u.Name, e
		}
		return u.Email, e
	}
	if kind == "group" {
		label, e := q.LockAppAccessGroupSubject(ctx, sqlc.LockAppAccessGroupSubjectParams{OrgID: org, ID: id})
		if errors.Is(e, pgx.ErrNoRows) {
			e = notFound()
		}
		return label, e
	}
	return "", apierr.BadRequest("invalid_grant_subject", "select one user or group")
}
func (s *Service) projectGrant(ctx context.Context, g sqlc.AppAccessGrant, now time.Time) (Grant, error) {
	app, err := s.GetApplication(ctx, g.OrgID, g.AppID)
	if err != nil {
		return Grant{}, err
	}
	available, err := sqlc.New(s.pool).AppAccessGrantSubjectAvailable(ctx, sqlc.AppAccessGrantSubjectAvailableParams{OrgID: g.OrgID, ID: g.ID})
	if err != nil {
		return Grant{}, err
	}
	return projectGrantValue(g, app.Draft.Name, available, now), nil
}
func projectGrantValue(g sqlc.AppAccessGrant, label string, available *bool, now time.Time) Grant {
	out := Grant{ID: g.ID, OrgID: g.OrgID, AppID: g.AppID, AppLabel: label, SubjectKind: g.SubjectKind, SubjectID: g.SubjectID, SubjectLabel: g.SubjectLabel, Enabled: g.Enabled, StartsAt: timePointer(g.StartsAt), ExpiresAt: timePointer(g.ExpiresAt), Version: g.Version, RevokedAt: timePointer(g.RevokedAt), CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt}
	switch {
	case g.RevokedAt.Valid:
		out.Status = "revoked"
	case available == nil || !*available:
		out.Status = "subject_unavailable"
	case !g.Enabled:
		out.Status = "disabled"
	case g.StartsAt.Valid && now.Before(g.StartsAt.Time):
		out.Status = "scheduled"
	case g.ExpiresAt.Valid && !now.Before(g.ExpiresAt.Time):
		out.Status = "expired"
	default:
		out.Status = "active"
	}
	return out
}
func (s *Service) GetGrant(ctx context.Context, org, id uuid.UUID) (Grant, error) {
	if e := s.requireActiveOrg(ctx, org); e != nil {
		return Grant{}, e
	}
	g, e := sqlc.New(s.pool).GetAppAccessGrant(ctx, sqlc.GetAppAccessGrantParams{OrgID: org, ID: id})
	if errors.Is(e, pgx.ErrNoRows) {
		return Grant{}, notFound()
	}
	if e != nil {
		return Grant{}, e
	}
	return s.projectGrant(ctx, g, s.now())
}
func (s *Service) ListGrants(ctx context.Context, org uuid.UUID, appID *uuid.UUID, subjectKind string, subjectID *uuid.UUID, limit, offset int32, filters ...GrantListFilter) ([]Grant, error) {
	if e := s.requireActiveOrg(ctx, org); e != nil {
		return nil, e
	}
	if limit < 1 || limit > 100 || offset < 0 || offset > 10000 || subjectKind != "" && subjectKind != "user" && subjectKind != "group" {
		return nil, apierr.BadRequest("invalid_pagination", "invalid grant filter or pagination")
	}
	if appID != nil {
		if _, e := s.GetApplication(ctx, org, *appID); e != nil {
			return nil, e
		}
	}
	if len(filters) > 1 {
		return nil, apierr.BadRequest("invalid_grant_filter", "one grant filter is supported")
	}
	filter := GrantListFilter{}
	if len(filters) == 1 {
		filter = filters[0]
	}
	filter, e := NormalizeGrantListFilter(filter)
	if e != nil {
		return nil, e
	}
	now := s.now()
	rows, e := sqlc.New(s.pool).ListFilteredAppAccessGrants(ctx, sqlc.ListFilteredAppAccessGrantsParams{OrgID: org, AppID: nullableID(appID), SubjectKind: subjectKind, SubjectID: nullableID(subjectID), Search: filter.Search, Status: filter.Status, View: filter.View, EvaluatedAt: now, PageLimit: limit, PageOffset: offset})
	if e != nil {
		return nil, e
	}
	out := make([]Grant, 0, len(rows))
	for _, row := range rows {
		// Use the same eligibility snapshot and evaluation time as the SQL filter.
		out = append(out, projectGrantValue(row.AppAccessGrant, row.AppLabel, &row.SubjectAvailable, now))
	}
	return out, nil
}
func (s *Service) CreateGrant(ctx context.Context, org, actor uuid.UUID, in GrantInput, entitled bool) (Grant, error) {
	return s.createGrant(ctx, org, actor, in, entitled, nil)
}
func (s *Service) createGrant(ctx context.Context, org, actor uuid.UUID, in GrantInput, entitled bool, before func(*sqlc.Queries) error) (Grant, error) {
	if in.AppID == uuid.Nil || in.SubjectID == uuid.Nil || in.SubjectKind != "user" && in.SubjectKind != "group" {
		return Grant{}, apierr.BadRequest("invalid_grant_subject", "select an application and one user or group")
	}
	if e := validWindow(in.StartsAt, in.ExpiresAt); e != nil {
		return Grant{}, e
	}
	var id uuid.UUID
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		if before != nil {
			if err := before(q); err != nil {
				return err
			}
		}
		if e := lockGrantOrg(ctx, q, org); e != nil {
			return e
		}
		if e := s.requireGrantFeature(ctx, q, org, entitled); e != nil {
			return e
		}
		if application, e := q.GetAppAccessApplication(ctx, sqlc.GetAppAccessApplicationParams{OrgID: org, ID: in.AppID}); errors.Is(e, pgx.ErrNoRows) {
			return notFound()
		} else if e != nil {
			return e
		} else if application.State != "draft" {
			return apierr.Conflict("application_archived", "archived application cannot receive grants")
		}
		label, e := lockSubject(ctx, q, org, in.SubjectID, in.SubjectKind)
		if e != nil {
			return e
		}
		g, e := createGrantRecord(ctx, q, org, actor, in, label)
		if e != nil {
			return e
		}
		id = g.ID
		return nil
	})
	if pgerr.IsUnique(e) {
		e = apierr.Conflict("grant_already_exists", "an unrevoked grant already exists for this application and subject")
	}
	if e != nil {
		return Grant{}, mapDB(e)
	}
	return s.GetGrant(ctx, org, id)
}
func (s *Service) UpdateGrant(ctx context.Context, org, actor, id uuid.UUID, in GrantUpdate, expectedVersion int64, entitled bool) (Grant, error) {
	return s.updateGrant(ctx, org, actor, id, in, expectedVersion, entitled, nil)
}
func (s *Service) updateGrant(ctx context.Context, org, actor, id uuid.UUID, in GrantUpdate, expectedVersion int64, entitled bool, before func(*sqlc.Queries) error) (Grant, error) {
	if e := validWindow(in.StartsAt, in.ExpiresAt); e != nil {
		return Grant{}, e
	}
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		if before != nil {
			if err := before(q); err != nil {
				return err
			}
		}
		if e := lockGrantOrg(ctx, q, org); e != nil {
			return e
		}
		g, e := q.GetAppAccessGrant(ctx, sqlc.GetAppAccessGrantParams{OrgID: org, ID: id})
		if errors.Is(e, pgx.ErrNoRows) {
			return notFound()
		}
		if e != nil {
			return e
		}
		if g.RevokedAt.Valid {
			return apierr.Conflict("grant_revoked", "revoked grants cannot be edited")
		}
		if g.Version != expectedVersion {
			return conflict()
		}
		// Taking access away remains available after opt-in/license/domain loss.
		disableOnly := !in.Enabled && sameTime(in.StartsAt, g.StartsAt) && sameTime(in.ExpiresAt, g.ExpiresAt)
		if !disableOnly {
			if e = s.requireGrantFeature(ctx, q, org, entitled); e != nil {
				return e
			}
			if _, e = lockSubject(ctx, q, org, g.SubjectID, g.SubjectKind); e != nil {
				return e
			}
		}
		// Directory deletion owns subject rows before its FK updates a grant.
		// Match that order; the immutable tuple read above is rechecked here.
		g, e = q.LockAppAccessGrant(ctx, sqlc.LockAppAccessGrantParams{OrgID: org, ID: id})
		if errors.Is(e, pgx.ErrNoRows) {
			return notFound()
		}
		if e != nil {
			return e
		}
		if g.RevokedAt.Valid {
			return apierr.Conflict("grant_revoked", "revoked grants cannot be edited")
		}
		if g.Version != expectedVersion {
			return conflict()
		}
		updated, e := q.UpdateAppAccessGrant(ctx, sqlc.UpdateAppAccessGrantParams{OrgID: org, ID: id, Enabled: in.Enabled, StartsAt: timestamp(in.StartsAt), ExpiresAt: timestamp(in.ExpiresAt)})
		if e != nil {
			return e
		}
		return auditGrant(ctx, q, actor, "app_access.grant_updated", updated)
	})
	if e != nil {
		return Grant{}, mapDB(e)
	}
	return s.GetGrant(ctx, org, id)
}
func (s *Service) RevokeGrant(ctx context.Context, org, actor, id uuid.UUID, expectedVersion int64) (Grant, error) {
	return s.revokeGrant(ctx, org, actor, id, expectedVersion, nil)
}
func (s *Service) revokeGrant(ctx context.Context, org, actor, id uuid.UUID, expectedVersion int64, before func(*sqlc.Queries) error) (Grant, error) {
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		if before != nil {
			if err := before(q); err != nil {
				return err
			}
		}
		if e := lockGrantOrg(ctx, q, org); e != nil {
			return e
		}
		g, e := q.LockAppAccessGrant(ctx, sqlc.LockAppAccessGrantParams{OrgID: org, ID: id})
		if errors.Is(e, pgx.ErrNoRows) {
			return notFound()
		}
		if e != nil {
			return e
		}
		if g.RevokedAt.Valid {
			return nil
		}
		if g.Version != expectedVersion {
			return conflict()
		}
		g, e = q.RevokeAppAccessGrant(ctx, sqlc.RevokeAppAccessGrantParams{OrgID: org, ID: id})
		if e != nil {
			return e
		}
		return auditGrant(ctx, q, actor, "app_access.grant_revoked", g)
	})
	if e != nil {
		return Grant{}, e
	}
	return s.GetGrant(ctx, org, id)
}
func (s *Service) EffectiveAccess(ctx context.Context, org, app, user uuid.UUID, entitled bool) (Preview, error) {
	out := Preview{EvaluatedAt: s.now(), MatchingGrantIDs: []uuid.UUID{}}
	a, e := s.GetApplication(ctx, org, app)
	if e != nil {
		return out, e
	}
	q := sqlc.New(s.pool)
	identity, e := q.AppAccessEvaluationUser(ctx, sqlc.AppAccessEvaluationUserParams{OrgID: org, ID: user})
	if errors.Is(e, pgx.ErrNoRows) {
		out.DenyReason = "membership_unavailable"
		return out, nil
	}
	if e != nil {
		return out, e
	}
	if identity.Status != "active" {
		out.DenyReason = "user_inactive"
		return out, nil
	}
	if identity.AccessRevokedAt.Valid {
		out.DenyReason = "membership_unavailable"
		return out, nil
	}
	matches, e := q.MatchingAppAccessGrants(ctx, sqlc.MatchingAppAccessGrantsParams{OrgID: org, AppID: app, UserID: user, EvaluatedAt: out.EvaluatedAt})
	if e != nil {
		return out, e
	}
	for _, g := range matches {
		out.MatchingGrantIDs = append(out.MatchingGrantIDs, g.ID)
		if g.ExpiresAt.Valid && (out.NextExpiryAt == nil || g.ExpiresAt.Time.Before(*out.NextExpiryAt)) {
			out.NextExpiryAt = timePointer(g.ExpiresAt)
		}
	}
	out.GrantMatch = len(matches) > 0
	settings, e := s.GetSettings(ctx, org)
	if e != nil {
		return out, e
	}
	roles := identity.Roles
	if len(roles) == 0 {
		roles = []string{identity.Role}
	}
	switch {
	case !entitled:
		out.DenyReason = "feature_unavailable"
	case !settings.Enabled:
		out.DenyReason = "feature_disabled"
	case !identity.EmailVerifiedAt.Valid:
		out.DenyReason = "email_not_verified"
	case identity.MustChangePassword:
		out.DenyReason = "password_change_required"
	case !rbac.CanAny(roles, rbac.PermAppAccessUse):
		out.DenyReason = "no_use_permission"
	case !out.GrantMatch:
		out.DenyReason = "no_active_grant"
	case a.State == "archived":
		out.DenyReason = "app_unpublished"
	default:
		if _, err := s.lookupServingApplication(ctx, org, app, entitled); err == nil {
			if a.RequireMFA {
				// A user-only preview cannot prove assurance on a specific parent login.
				out.DenyReason = "mfa_required"
			} else {
				out.AccessAllowed = true
				out.DenyReason = ""
			}
		} else {
			var ae *apierr.Error
			if errors.As(err, &ae) && ae.Status >= 500 {
				return out, err
			}
			if a.PublicationState == "published" {
				out.DenyReason = "connector_unavailable"
			} else {
				out.DenyReason = "app_unpublished"
			}
		}
	}
	return out, nil
}
func (s *Service) RevokeImpact(ctx context.Context, org, id uuid.UUID) (GrantImpact, error) {
	out := GrantImpact{EvaluatedAt: s.now()}
	if e := s.requireActiveOrg(ctx, org); e != nil {
		return out, e
	}
	q := sqlc.New(s.pool)
	g, e := q.GetAppAccessGrant(ctx, sqlc.GetAppAccessGrantParams{OrgID: org, ID: id})
	if errors.Is(e, pgx.ErrNoRows) {
		return out, notFound()
	}
	if e != nil {
		return out, e
	}
	out.GrantVersion = g.Version
	// Derive accepted roles from the central permission union, not a parallel SQL role policy.
	roles := []string{}
	for role := range rbac.Policy() {
		if rbac.CanAny([]string{role}, rbac.PermAppAccessUse) {
			roles = append(roles, role)
		}
	}
	sort.Strings(roles)
	impact, e := q.AppAccessRevokeImpact(ctx, sqlc.AppAccessRevokeImpactParams{OrgID: org, GrantID: id, EvaluatedAt: out.EvaluatedAt, EligibleRoles: roles})
	if e == nil && impact.GrantVersion == 0 {
		return out, notFound()
	}
	out.GrantVersion = impact.GrantVersion
	out.MatchingUserCount = impact.MatchingUserCount
	out.UsersLosingGrantMatchCount = impact.UsersLosingGrantMatchCount
	return out, e
}

// createGrantRecord participates in its caller's transaction so a request
// decision, its explicit grant and both audit records commit together.
func createGrantRecord(ctx context.Context, q *sqlc.Queries, org, actor uuid.UUID, in GrantInput, label string) (sqlc.AppAccessGrant, error) {
	args := sqlc.CreateAppAccessGrantParams{OrgID: org, AppID: in.AppID, SubjectKind: in.SubjectKind, SubjectID: in.SubjectID, SubjectLabel: label, Enabled: in.Enabled, StartsAt: timestamp(in.StartsAt), ExpiresAt: timestamp(in.ExpiresAt)}
	if in.SubjectKind == "user" {
		args.UserID = nullableID(&in.SubjectID)
	} else {
		args.GroupID = nullableID(&in.SubjectID)
	}
	g, err := q.CreateAppAccessGrant(ctx, args)
	if err != nil {
		return g, err
	}
	return g, auditGrant(ctx, q, actor, "app_access.grant_created", g)
}

// auditGrant captures safe event-time values in the append-only audit row.
// Grant history remains intelligible after its operational row is retained out.
func auditGrant(ctx context.Context, q *sqlc.Queries, actor uuid.UUID, action string, g sqlc.AppAccessGrant) error {
	snapshot := map[string]any{"id": g.ID, "org_id": g.OrgID, "app_id": g.AppID, "subject_kind": g.SubjectKind, "subject_id": g.SubjectID, "subject_label": g.SubjectLabel, "enabled": g.Enabled, "starts_at": timePointer(g.StartsAt), "expires_at": timePointer(g.ExpiresAt), "revoked_at": timePointer(g.RevokedAt), "version": g.Version, "created_at": g.CreatedAt, "updated_at": g.UpdatedAt}
	metadata, err := json.Marshal(map[string]any{"version": g.Version, "snapshot_kind": "event_state", "grant": snapshot})
	if err != nil {
		return err
	}
	kind, target := "app_access", g.ID.String()
	_, err = q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{OrgID: nullableID(&g.OrgID), ActorUserID: nullableID(&actor), Action: action, TargetType: &kind, TargetID: &target, Metadata: metadata})
	return err
}
