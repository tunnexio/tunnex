package appaccess

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type CompanyPerson struct {
	ID          uuid.UUID
	Name, Email string
	Available   bool
}
type AccessManagement struct {
	AppID          uuid.UUID
	Version        int64
	CatalogVisible bool
	AppAdminUserID *uuid.UUID
	AppAdmin       *CompanyPerson
}
type AccessRequest struct {
	ID, AppID                      uuid.UUID
	AppName                        string
	Requester                      CompanyPerson
	AppAdmin                       *CompanyPerson
	Status, Reason, DecisionReason string
	Version                        int64
	CreatedAt                      time.Time
	DecidedAt                      *time.Time
	DecidedBy, GrantID             *uuid.UUID
}
type AccessRequests struct {
	Items        []AccessRequest
	PendingCount int64
}
type CompanyApp struct {
	MyApp
	AppAdmin      *CompanyPerson
	AccessGranted bool
	LatestRequest *AccessRequest
}
type CompanyApps struct {
	Items        []CompanyApp
	Availability string
}
type ManagedApps struct {
	Items               []ManagedApp
	CanViewApplications bool
	CanManageGrants     bool
}
type ManagedApp struct {
	ID                                   uuid.UUID
	Name, Description, Icon, IconDataURL string
	PendingCount                         int64
}
type GrantSubject struct {
	ID                uuid.UUID
	Name, Email, Kind string
}
type AccessDecision struct {
	ExpectedVersion  int64
	Decision, Reason string
	ExpiresAt        *time.Time
}

func companyPage(search string, limit, offset int32) error {
	if limit < 1 || limit > 100 || offset < 0 || offset > 10000 || !utf8.ValidString(search) || utf8.RuneCountInString(search) > 100 {
		return apierr.BadRequest("invalid_pagination", "invalid search or pagination")
	}
	return nil
}
func companyReason(reason string) (string, error) {
	reason = strings.TrimSpace(reason)
	if !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > 1000 || strings.IndexFunc(reason, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) >= 0 {
		return "", apierr.BadRequest("invalid_reason", "reason must contain at most 1000 characters")
	}
	return reason, nil
}
func companyUUID(id pgtype.UUID) *uuid.UUID {
	if !id.Valid {
		return nil
	}
	out := uuid.UUID(id.Bytes)
	return &out
}
func companyRoles(a sqlc.LockAppAccessCompanyActorRow) []string {
	if len(a.Roles) > 0 {
		return a.Roles
	}
	return []string{a.Role}
}
func companyActor(ctx context.Context, q *sqlc.Queries, org, actor uuid.UUID) (sqlc.LockAppAccessCompanyActorRow, error) {
	if err := lockGrantOrg(ctx, q, org); err != nil {
		return sqlc.LockAppAccessCompanyActorRow{}, err
	}
	a, err := q.LockAppAccessCompanyActor(ctx, sqlc.LockAppAccessCompanyActorParams{OrgID: org, ID: actor})
	if errors.Is(err, pgx.ErrNoRows) {
		return a, notFound()
	}
	return a, err
}

// Lock current human membership before the application. Membership deletion
// owns directory rows before its FK detaches the app administrator.
func companyAuthority(ctx context.Context, q *sqlc.Queries, org, actor, app uuid.UUID, management bool) (sqlc.GetAppAccessManagementRow, error) {
	a, err := companyActor(ctx, q, org, actor)
	if err != nil {
		return sqlc.GetAppAccessManagementRow{}, err
	}
	if _, err = q.LockAppAccessApplication(ctx, sqlc.LockAppAccessApplicationParams{OrgID: org, ID: app}); errors.Is(err, pgx.ErrNoRows) {
		return sqlc.GetAppAccessManagementRow{}, notFound()
	} else if err != nil {
		return sqlc.GetAppAccessManagementRow{}, err
	}
	current, err := q.GetAppAccessManagement(ctx, sqlc.GetAppAccessManagementParams{OrgID: org, ID: app})
	if err != nil {
		return current, err
	}
	global := rbac.CanAny(companyRoles(a), rbac.PermAppAccessGrant)
	if management {
		if !global || !rbac.CanAny(companyRoles(a), rbac.PermAppAccessManage) {
			return current, apierr.Forbidden("forbidden", "application management and grant permissions are required")
		}
	} else if !global && (!current.AppAdminUserID.Valid || uuid.UUID(current.AppAdminUserID.Bytes) != actor || !current.AdminAvailable) {
		return current, notFound()
	}
	return current, nil
}
func companyManagement(row sqlc.GetAppAccessManagementRow) AccessManagement {
	out := AccessManagement{AppID: row.ID, Version: row.Version, CatalogVisible: row.CatalogVisible, AppAdminUserID: companyUUID(row.AppAdminUserID)}
	if out.AppAdminUserID != nil {
		out.AppAdmin = &CompanyPerson{ID: *out.AppAdminUserID, Name: row.AdminName, Email: row.AdminEmail, Available: row.AdminAvailable}
	}
	return out
}
func (s *Service) GetAccessManagement(ctx context.Context, org, actor, app uuid.UUID) (AccessManagement, error) {
	var out AccessManagement
	err := s.transaction(ctx, func(q *sqlc.Queries) error {
		row, err := companyAuthority(ctx, q, org, actor, app, true)
		if err == nil {
			out = companyManagement(row)
		}
		return err
	})
	return out, err
}
func (s *Service) UpdateAccessManagement(ctx context.Context, org, actor, app uuid.UUID, visible bool, admin *uuid.UUID, expected int64) (AccessManagement, error) {
	var out AccessManagement
	if expected < 1 || admin != nil && *admin == uuid.Nil {
		return out, apierr.BadRequest("invalid_request", "current version and a valid App admin are required")
	}
	err := s.transaction(ctx, func(q *sqlc.Queries) error {
		// A stale inactive assignment must never prevent hiding the catalog entry.
		// Read the old binding before directory locks; the app version is rechecked below.
		previous, err := q.GetAppAccessManagement(ctx, sqlc.GetAppAccessManagementParams{OrgID: org, ID: app})
		if errors.Is(err, pgx.ErrNoRows) {
			return notFound()
		}
		if err != nil {
			return err
		}
		if previous.Version != expected {
			return conflict()
		}
		unchangedAdmin := admin == nil && !previous.AppAdminUserID.Valid || admin != nil && previous.AppAdminUserID.Valid && *admin == uuid.UUID(previous.AppAdminUserID.Bytes)
		if admin != nil && (!unchangedAdmin || visible && !previous.CatalogVisible) {
			if _, err := lockSubject(ctx, q, org, *admin, "user"); err != nil {
				return err
			}
		}
		row, err := companyAuthority(ctx, q, org, actor, app, true)
		if err != nil {
			return err
		}
		if row.State != "draft" {
			return apierr.Conflict("application_archived", "archived application cannot be changed")
		}
		if row.Version != expected {
			return conflict()
		}
		sameAdmin := admin == nil && !row.AppAdminUserID.Valid || admin != nil && row.AppAdminUserID.Valid && *admin == uuid.UUID(row.AppAdminUserID.Bytes)
		if visible && !row.CatalogVisible && admin == nil {
			return apierr.Conflict("app_admin_required", "assign an active organization user before enabling Company apps")
		}
		if sameAdmin && visible == row.CatalogVisible {
			out = companyManagement(row)
			return nil
		}
		changed, err := q.UpdateAppAccessManagement(ctx, sqlc.UpdateAppAccessManagementParams{OrgID: org, AppID: app, CatalogVisible: visible, AppAdminUserID: nullableID(admin), ExpectedVersion: expected})
		if err != nil {
			return err
		}
		if changed != 1 {
			return conflict()
		}
		if err = auditAccessManagement(ctx, q, org, actor, app, row, visible, admin, expected+1); err != nil {
			return err
		}
		row, err = q.GetAppAccessManagement(ctx, sqlc.GetAppAccessManagementParams{OrgID: org, ID: app})
		if err == nil {
			out = companyManagement(row)
		}
		return err
	})
	return out, mapDB(err)
}
func projectAccessRequest(ctx context.Context, q *sqlc.Queries, org, id uuid.UUID) (AccessRequest, error) {
	row, err := q.GetAppAccessRequest(ctx, sqlc.GetAppAccessRequestParams{OrgID: org, ID: id})
	if errors.Is(err, pgx.ErrNoRows) {
		return AccessRequest{}, notFound()
	}
	if err != nil {
		return AccessRequest{}, err
	}
	management, err := q.GetAppAccessManagement(ctx, sqlc.GetAppAccessManagementParams{OrgID: org, ID: row.AppID})
	if err != nil {
		return AccessRequest{}, err
	}
	return AccessRequest{ID: row.ID, AppID: row.AppID, AppName: row.AppName, Requester: CompanyPerson{ID: row.RequesterUserID, Name: row.RequesterName, Email: row.RequesterEmail, Available: row.RequesterAvailable}, AppAdmin: companyManagement(management).AppAdmin, Status: row.Status, Reason: row.Reason, DecisionReason: row.DecisionReason, Version: row.Version, CreatedAt: row.CreatedAt, DecidedAt: timePointer(row.DecidedAt), DecidedBy: companyUUID(row.DecidedBy), GrantID: companyUUID(row.ApprovedGrantID)}, nil
}
func (s *Service) CompanyApps(ctx context.Context, org, user uuid.UUID, parentID, search string, limit, offset int32, entitled bool) (CompanyApps, error) {
	out := CompanyApps{Items: []CompanyApp{}, Availability: "available"}
	if err := companyPage(search, limit, offset); err != nil {
		return out, err
	}
	parent, _, err := s.validateParent(ctx, user, parentID, 0)
	if err != nil {
		var typed *apierr.Error
		if errors.As(err, &typed) && typed.Code == "app_login_required" {
			out.Availability = "parent_unavailable"
			return out, nil
		}
		return out, err
	}
	setting, err := s.GetSettings(ctx, org)
	if err != nil {
		return out, err
	}
	switch {
	case !entitled:
		out.Availability = "feature_unavailable"
	case !setting.Enabled:
		out.Availability = "feature_disabled"
	case !setting.DomainReady:
		out.Availability = "domain_unavailable"
	}
	if out.Availability != "available" {
		return out, nil
	}
	err = s.transaction(ctx, func(q *sqlc.Queries) error {
		actor, err := companyActor(ctx, q, org, user)
		if err != nil {
			return err
		}
		if !rbac.CanAny(companyRoles(actor), rbac.PermAppAccessUse) {
			return apierr.Forbidden("forbidden", "application use permission is required")
		}
		rows, err := q.ListAppAccessCompanyCandidates(ctx, sqlc.ListAppAccessCompanyCandidatesParams{OrgID: org, UserID: nullableID(&user), EvaluatedAt: s.now(), Search: search, PageLimit: limit, PageOffset: offset})
		if err != nil {
			return err
		}
		for _, row := range rows {
			current, err := q.GetAppAccessManagement(ctx, sqlc.GetAppAccessManagementParams{OrgID: org, ID: row.ID})
			if err != nil {
				return err
			}
			app := CompanyApp{MyApp: MyApp{ID: row.ID, Name: row.Name, Description: row.Description, Icon: row.Icon, IconDataURL: row.IconDataUrl, RequireMFA: row.RequireMfa}, AppAdmin: companyManagement(current).AppAdmin, AccessGranted: row.AccessGranted}
			if row.AccessGranted {
				app.LaunchURL = "https://" + row.Hostname + "/__tunnex_app/start"
			}
			id, err := q.LatestOwnAppAccessRequest(ctx, sqlc.LatestOwnAppAccessRequestParams{OrgID: org, AppID: row.ID, RequesterUserID: user})
			if err == nil {
				request, err := projectAccessRequest(ctx, q, org, id)
				if err != nil {
					return err
				}
				app.LatestRequest = &request
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			out.Items = append(out.Items, app)
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	// Enrollment is account-wide and uses the same pool; resolve it only after
	// releasing the catalog transaction's connection. Launch rechecks all policy.
	for i := range out.Items {
		if !out.Items[i].AccessGranted {
			continue
		}
		status, err := s.applicationMFAStatus(ctx, out.Items[i].RequireMFA, parent)
		if err != nil {
			return CompanyApps{}, err
		}
		out.Items[i].MFARequired = status.Required
		out.Items[i].MFASetupRequired = status.SetupRequired
	}
	return out, nil
}
func (s *Service) ManagedApps(ctx context.Context, org, actor uuid.UUID, app *uuid.UUID, limit, offset int32) (ManagedApps, error) {
	out := ManagedApps{Items: []ManagedApp{}}
	if err := companyPage("", limit, offset); err != nil {
		return out, err
	}
	err := s.transaction(ctx, func(q *sqlc.Queries) error {
		person, err := companyActor(ctx, q, org, actor)
		if err != nil {
			return err
		}
		// Navigation hints use the same current membership as the scoped query.
		// Assignment alone never confers either organization-wide permission.
		out.CanViewApplications = rbac.CanAny(companyRoles(person), rbac.PermAppAccessView)
		out.CanManageGrants = rbac.CanAny(companyRoles(person), rbac.PermAppAccessGrant)
		rows, err := q.ListManagedAppAccessApps(ctx, sqlc.ListManagedAppAccessAppsParams{OrgID: org, ActorID: nullableID(&actor), AppID: nullableID(app), GlobalGrant: out.CanManageGrants, PageLimit: limit, PageOffset: offset})
		if err != nil {
			return err
		}
		for _, row := range rows {
			out.Items = append(out.Items, ManagedApp{ID: row.ID, Name: row.Name, Description: row.Description, Icon: row.Icon, IconDataURL: row.IconDataUrl, PendingCount: row.PendingCount})
		}
		return nil
	})
	return out, err
}
func (s *Service) AccessRequests(ctx context.Context, org, actor uuid.UUID, own bool, status string, app *uuid.UUID, limit, offset int32) (AccessRequests, error) {
	out := AccessRequests{Items: []AccessRequest{}}
	if err := companyPage("", limit, offset); err != nil {
		return out, err
	}
	if status != "" && status != "pending" && status != "approved" && status != "rejected" {
		return out, apierr.BadRequest("invalid_status", "invalid request status")
	}
	err := s.transaction(ctx, func(q *sqlc.Queries) error {
		person, err := companyActor(ctx, q, org, actor)
		if err != nil {
			return err
		}
		global := rbac.CanAny(companyRoles(person), rbac.PermAppAccessGrant)
		ids, err := q.ListAppAccessRequestIDs(ctx, sqlc.ListAppAccessRequestIDsParams{OrgID: org, ActorID: actor, Own: own, GlobalGrant: global, Status: status, AppID: nullableID(app), PageLimit: limit, PageOffset: offset})
		if err != nil {
			return err
		}
		for _, id := range ids {
			row, err := projectAccessRequest(ctx, q, org, id)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, row)
		}
		out.PendingCount, err = q.CountPendingAppAccessRequests(ctx, sqlc.CountPendingAppAccessRequestsParams{OrgID: org, ActorID: actor, Own: own, GlobalGrant: global, AppID: nullableID(app)})
		return err
	})
	return out, err
}
func (s *Service) CreateAccessRequest(ctx context.Context, org, actor, app uuid.UUID, reason string, entitled bool) (AccessRequest, error) {
	var out AccessRequest
	reason, err := companyReason(reason)
	if err != nil {
		return out, err
	}
	err = s.transaction(ctx, func(q *sqlc.Queries) error {
		person, err := companyActor(ctx, q, org, actor)
		if err != nil {
			return err
		}
		if !rbac.CanAny(companyRoles(person), rbac.PermAppAccessUse) {
			return apierr.Forbidden("forbidden", "application use permission is required")
		}
		if _, err = q.LockAppAccessApplication(ctx, sqlc.LockAppAccessApplicationParams{OrgID: org, ID: app}); errors.Is(err, pgx.ErrNoRows) {
			return notFound()
		} else if err != nil {
			return err
		}
		publishedName, err := q.AppAccessCompanyAppPublished(ctx, sqlc.AppAccessCompanyAppPublishedParams{OrgID: org, ID: app})
		if errors.Is(err, pgx.ErrNoRows) {
			return notFound()
		}
		if err != nil {
			return err
		}
		if err = s.requireGrantFeature(ctx, q, org, entitled); err != nil {
			return err
		}
		pending, err := q.PendingOwnAppAccessRequest(ctx, sqlc.PendingOwnAppAccessRequestParams{OrgID: org, AppID: app, RequesterUserID: actor})
		if err == nil {
			out, err = projectAccessRequest(ctx, q, org, pending)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		matches, err := q.MatchingAppAccessGrants(ctx, sqlc.MatchingAppAccessGrantsParams{OrgID: org, AppID: app, UserID: actor, EvaluatedAt: s.now()})
		if err != nil {
			return err
		}
		if len(matches) > 0 {
			return apierr.Conflict("access_already_granted", "you already have access to this application")
		}
		row, err := q.CreateAppAccessRequest(ctx, sqlc.CreateAppAccessRequestParams{OrgID: org, AppID: app, RequesterUserID: actor, RequesterName: person.Name, RequesterEmail: person.Email, Reason: reason, AppName: publishedName})
		if err != nil {
			return err
		}
		if err = audit(ctx, q, org, actor, row.ID.String(), "app_access.request_created", row.Version); err != nil {
			return err
		}
		out, err = projectAccessRequest(ctx, q, org, row.ID)
		return err
	})
	return out, mapDB(err)
}
func (s *Service) DecideAccessRequest(ctx context.Context, org, actor, id uuid.UUID, in AccessDecision, entitled bool) (AccessRequest, error) {
	var out AccessRequest
	reason, err := companyReason(in.Reason)
	if err != nil {
		return out, err
	}
	if in.ExpectedVersion < 1 || in.Decision != "approved" && in.Decision != "rejected" {
		return out, apierr.BadRequest("invalid_decision", "select approve or reject with the current request version")
	}
	if err = validWindow(nil, in.ExpiresAt); err != nil {
		return out, err
	}
	if in.Decision == "approved" && in.ExpiresAt != nil && !in.ExpiresAt.After(s.now()) {
		return out, apierr.BadRequest("invalid_grant_window", "approval expiry must be in the future")
	}
	err = s.transaction(ctx, func(q *sqlc.Queries) error {
		// Read only the immutable app/requester binding; authorization precedes any projection.
		selected, err := q.GetAppAccessRequest(ctx, sqlc.GetAppAccessRequestParams{OrgID: org, ID: id})
		if errors.Is(err, pgx.ErrNoRows) {
			return notFound()
		}
		if err != nil {
			return err
		}
		if in.Decision == "approved" && selected.Status == "pending" {
			if !selected.RequesterMembershipUserID.Valid {
				return apierr.Conflict("requester_unavailable", "the original requesting membership is unavailable")
			}
			if _, err = lockSubject(ctx, q, org, selected.RequesterUserID, "user"); err != nil {
				return err
			}
		}
		current, err := companyAuthority(ctx, q, org, actor, selected.AppID, false)
		if err != nil {
			return err
		}
		row, err := q.LockAppAccessRequest(ctx, sqlc.LockAppAccessRequestParams{OrgID: org, ID: id})
		if err != nil {
			return err
		}
		if row.Status != "pending" {
			if row.Status != in.Decision {
				return apierr.Conflict("request_already_decided", "this request already has a different decision")
			}
			out, err = projectAccessRequest(ctx, q, org, id)
			return err
		}
		if row.Version != in.ExpectedVersion {
			return conflict()
		}
		var grantID *uuid.UUID
		if in.Decision == "approved" {
			if current.State != "draft" {
				return apierr.Conflict("application_archived", "archived application cannot receive grants")
			}
			if !row.RequesterMembershipUserID.Valid {
				return apierr.Conflict("requester_unavailable", "the original requesting membership is unavailable")
			}
			if err = s.requireGrantFeature(ctx, q, org, entitled); err != nil {
				return err
			}
			label, err := lockSubject(ctx, q, org, row.RequesterUserID, "user")
			if err != nil {
				return err
			}
			matches, err := q.MatchingAppAccessGrants(ctx, sqlc.MatchingAppAccessGrantsParams{OrgID: org, AppID: row.AppID, UserID: row.RequesterUserID, EvaluatedAt: s.now()})
			if err != nil {
				return err
			}
			if len(matches) > 0 {
				id := matches[0].ID
				grantID = &id
			} else {
				existing, err := q.GetCurrentAppAccessUserGrant(ctx, sqlc.GetCurrentAppAccessUserGrantParams{OrgID: org, AppID: row.AppID, SubjectID: row.RequesterUserID})
				if errors.Is(err, pgx.ErrNoRows) {
					created, err := createGrantRecord(ctx, q, org, actor, GrantInput{AppID: row.AppID, SubjectKind: "user", SubjectID: row.RequesterUserID, Enabled: true, ExpiresAt: in.ExpiresAt}, label)
					if err != nil {
						return err
					}
					grantID = &created.ID
				} else if err != nil {
					return err
				} else {
					updated, err := q.UpdateAppAccessGrant(ctx, sqlc.UpdateAppAccessGrantParams{OrgID: org, ID: existing.ID, Enabled: true, ExpiresAt: timestamp(in.ExpiresAt)})
					if err != nil {
						return err
					}
					if err = auditGrant(ctx, q, actor, "app_access.grant_updated", updated); err != nil {
						return err
					}
					grantID = &updated.ID
				}
			}
		}
		changed, err := q.DecideAppAccessRequest(ctx, sqlc.DecideAppAccessRequestParams{OrgID: org, ID: id, Status: in.Decision, DecisionReason: reason, DecidedBy: nullableID(&actor), GrantID: nullableID(grantID), ExpectedVersion: in.ExpectedVersion})
		if err != nil {
			return err
		}
		if changed != 1 {
			return conflict()
		}
		if err = audit(ctx, q, org, actor, id.String(), "app_access.request_"+in.Decision, in.ExpectedVersion+1); err != nil {
			return err
		}
		out, err = projectAccessRequest(ctx, q, org, id)
		return err
	})
	return out, mapDB(err)
}
func (s *Service) GrantSubjects(ctx context.Context, org, actor, app uuid.UUID, kind, search string, limit, offset int32) ([]GrantSubject, error) {
	out := []GrantSubject{}
	if err := companyPage(search, limit, offset); err != nil {
		return out, err
	}
	if kind != "user" && kind != "group" {
		return out, apierr.BadRequest("invalid_grant_subject", "select users or groups")
	}
	err := s.transaction(ctx, func(q *sqlc.Queries) error {
		if _, err := companyAuthority(ctx, q, org, actor, app, false); err != nil {
			return err
		}
		if kind == "user" {
			rows, err := q.ListAppAccessGrantUserSubjects(ctx, sqlc.ListAppAccessGrantUserSubjectsParams{OrgID: org, Search: search, PageLimit: limit, PageOffset: offset})
			if err != nil {
				return err
			}
			for _, r := range rows {
				out = append(out, GrantSubject{ID: r.ID, Name: r.Name, Email: r.Email, Kind: kind})
			}
		} else {
			rows, err := q.ListAppAccessGrantGroupSubjects(ctx, sqlc.ListAppAccessGrantGroupSubjectsParams{OrgID: org, Search: search, PageLimit: limit, PageOffset: offset})
			if err != nil {
				return err
			}
			for _, r := range rows {
				out = append(out, GrantSubject{ID: r.ID, Name: r.Name, Kind: kind})
			}
		}
		return nil
	})
	return out, err
}
func (s *Service) ManagedGrants(ctx context.Context, org, actor, app uuid.UUID, limit, offset int32, filters ...GrantListFilter) ([]Grant, error) {
	out := []Grant{}
	if err := companyPage("", limit, offset); err != nil {
		return out, err
	}
	if len(filters) > 1 {
		return out, apierr.BadRequest("invalid_grant_filter", "one grant filter is supported")
	}
	filter := GrantListFilter{}
	if len(filters) == 1 {
		filter = filters[0]
	}
	filter, err := NormalizeGrantListFilter(filter)
	if err != nil {
		return out, err
	}
	err = s.transaction(ctx, func(q *sqlc.Queries) error {
		if _, err := companyAuthority(ctx, q, org, actor, app, false); err != nil {
			return err
		}
		now := s.now()
		rows, err := q.ListFilteredAppAccessGrants(ctx, sqlc.ListFilteredAppAccessGrantsParams{OrgID: org, AppID: nullableID(&app), PageLimit: limit, PageOffset: offset, View: filter.View, Status: filter.Status, Search: filter.Search, EvaluatedAt: now})
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, projectGrantValue(row.AppAccessGrant, row.AppLabel, &row.SubjectAvailable, now))
		}
		return nil
	})
	return out, err
}

// Directory deletion owns the grant subject before its FK touches grants and
// app assignment. Hold that same subject first, even for disable/revoke.
func managedGrantCheck(ctx context.Context, org, actor, app uuid.UUID, grant *uuid.UUID, input *GrantInput) func(*sqlc.Queries) error {
	return func(q *sqlc.Queries) error {
		kind, subject := "", uuid.Nil
		if input != nil {
			kind, subject = input.SubjectKind, input.SubjectID
		}
		if grant != nil {
			g, err := q.GetAppAccessGrant(ctx, sqlc.GetAppAccessGrantParams{OrgID: org, ID: *grant})
			if errors.Is(err, pgx.ErrNoRows) {
				return notFound()
			}
			if err != nil {
				return err
			}
			if g.AppID != app {
				return notFound()
			}
			kind, subject = g.SubjectKind, g.SubjectID
		}
		if kind == "user" {
			_, err := q.LockAppAccessGrantUserDirectory(ctx, sqlc.LockAppAccessGrantUserDirectoryParams{OrgID: org, ID: subject})
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		} else if kind == "group" {
			_, err := q.LockAppAccessGroupSubject(ctx, sqlc.LockAppAccessGroupSubjectParams{OrgID: org, ID: subject})
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		_, err := companyAuthority(ctx, q, org, actor, app, false)
		return err
	}
}
func (s *Service) CreateManagedGrant(ctx context.Context, org, actor, app uuid.UUID, in GrantInput, entitled bool) (Grant, error) {
	if in.AppID != app {
		return Grant{}, apierr.BadRequest("application_mismatch", "grant application must match the requested application")
	}
	return s.createGrant(ctx, org, actor, in, entitled, managedGrantCheck(ctx, org, actor, app, nil, &in))
}
func (s *Service) UpdateManagedGrant(ctx context.Context, org, actor, app, id uuid.UUID, in GrantUpdate, expected int64, entitled bool) (Grant, error) {
	if expected < 1 {
		return Grant{}, apierr.BadRequest("invalid_version", "expected version must be positive")
	}
	return s.updateGrant(ctx, org, actor, id, in, expected, entitled, managedGrantCheck(ctx, org, actor, app, &id, nil))
}
func (s *Service) RevokeManagedGrant(ctx context.Context, org, actor, app, id uuid.UUID, expected int64) (Grant, error) {
	if expected < 1 {
		return Grant{}, apierr.BadRequest("invalid_version", "expected version must be positive")
	}
	return s.revokeGrant(ctx, org, actor, id, expected, managedGrantCheck(ctx, org, actor, app, &id, nil))
}

func auditAccessManagement(ctx context.Context, q *sqlc.Queries, org, actor, app uuid.UUID, previous sqlc.GetAppAccessManagementRow, visible bool, admin *uuid.UUID, version int64) error {
	metadata, err := json.Marshal(map[string]any{"version": version, "catalog_visible": visible, "previous_catalog_visible": previous.CatalogVisible, "app_admin_user_id": admin, "previous_app_admin_user_id": companyUUID(previous.AppAdminUserID)})
	if err != nil {
		return err
	}
	kind, target := "app_access", app.String()
	_, err = q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{OrgID: nullableID(&org), ActorUserID: nullableID(&actor), Action: "app_access.management_updated", TargetType: &kind, TargetID: &target, Metadata: metadata})
	return err
}
