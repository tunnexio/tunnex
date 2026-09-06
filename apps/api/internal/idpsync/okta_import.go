package idpsync

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgtype"
	"net/url"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/idpsyncspec"
)

// oktaConnectionMatches binds directory ownership to an exact tested Okta
// connection. ID-token subjects, never access-token subjects or email, identify users.
func oktaConnectionMatches(c sqlc.SsoConnection, org uuid.UUID, origin string) bool {
	u, e := url.Parse(c.IssuerUrl)
	return e == nil && c.OrgID == org && c.Provider == "okta" && c.Enabled && c.TestedRevision != nil && *c.TestedRevision == c.Revision && u.Scheme+"://"+u.Host == origin
}

// ResolveDirectoryMember is used for Okta in place of email-based resolution.
// Creation and its first mapped grant are one transaction; collisions never adopt
// an unrelated global account. Existing links survive entitlement expiry.
func (s *Service) ResolveDirectoryMember(ctx context.Context, org, group uuid.UUID, provider string, m DirectoryMember) (uid uuid.UUID, found bool, err error) {
	if provider != "okta" {
		return s.ResolveOrgUser(ctx, org, m.Email)
	}
	cfg, e := s.q.GetIdpSyncConfig(ctx, sqlc.GetIdpSyncConfigParams{OrgID: org, Provider: provider})
	if e != nil {
		return uid, false, e
	}
	if !cfg.SsoConnectionID.Valid || cfg.OktaOrgUrl == nil {
		return uid, false, errors.New("Okta directory connection is missing")
	}
	connection := uuid.UUID(cfg.SsoConnectionID.Bytes)
	created := false
	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		c, e := q.LockSSOConnection(ctx, connection)
		if e != nil {
			return e
		}
		// Read current configuration after acquiring the shared namespace lock.
		fresh, e := q.GetIdpSyncConfig(ctx, sqlc.GetIdpSyncConfigParams{OrgID: org, Provider: provider})
		if e != nil {
			return e
		}
		if fresh.SsoConnectionID != cfg.SsoConnectionID || fresh.OktaOrgUrl == nil || *fresh.OktaOrgUrl != *cfg.OktaOrgUrl {
			return errors.New("Okta directory configuration changed; retry sync")
		}
		uid, e = q.GetSSOConnectionIdentity(ctx, sqlc.GetSSOConnectionIdentityParams{ConnectionID: connection, IssuerUrl: c.IssuerUrl, Subject: m.ExternalID})
		if e == nil {
			found = true
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if m.Status != StatusActive || !fresh.Enabled || !s.mayProvision() {
			return nil
		}
		if !oktaConnectionMatches(c, org, *fresh.OktaOrgUrl) {
			return errors.New("Okta SSO connection must be tested and enabled for this directory")
		}
		if _, e = q.LockDirectoryMappedGroup(ctx, sqlc.LockDirectoryMappedGroupParams{ID: group, OrgID: org, IdpProvider: &provider}); e != nil {
			return e
		}
		if _, e = q.GetUserByEmail(ctx, m.Email); e == nil {
			return apierr.New(409, "directory_identity_conflict", "an existing account requires authenticated company-sign-in linking before directory import")
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		// Recheck at the start of the additive transaction, after lock waits/reads.
		if !s.mayProvision() {
			return nil
		}
		u, e := q.CreateUser(ctx, sqlc.CreateUserParams{Email: m.Email, Name: m.Email})
		if e != nil {
			return e
		}
		uid = u.ID
		if e = q.CreateDirectoryMembership(ctx, sqlc.CreateDirectoryMembershipParams{OrgID: org, UserID: uid}); e != nil {
			return e
		}
		if e = q.ImportSSOConnectionIdentity(ctx, sqlc.ImportSSOConnectionIdentityParams{ConnectionID: connection, IssuerUrl: c.IssuerUrl, Subject: m.ExternalID, UserID: uid}); e != nil {
			return e
		}
		if e = q.RemoveImportedBootstrapSource(ctx, sqlc.RemoveImportedBootstrapSourceParams{OrgID: org, UserID: uid}); e != nil {
			return e
		}
		if _, e = q.AddIdpGroupMember(ctx, sqlc.AddIdpGroupMemberParams{OrgID: org, GroupID: group, UserID: uid, IdpExternalID: &m.ExternalID}); e != nil {
			return e
		}
		if e = q.AddIdpAccessSource(ctx, sqlc.AddIdpAccessSourceParams{OrgID: org, UserID: uid, SourceKey: group.String()}); e != nil {
			return e
		}
		// Audit within the same transaction as identity and membership creation.
		metadata, _ := json.Marshal(map[string]string{"provider": "okta", "connection_id": connection.String(), "group_id": group.String(), "cause": "present_in_mapped_directory_group"})
		actor, target, targetID := "idp-sync", "user", uid.String()
		if _, e = q.InsertSystemAuditLog(ctx, sqlc.InsertSystemAuditLogParams{OrgID: pgtype.UUID{Bytes: org, Valid: true}, ActorSystem: &actor, Action: "directory.user_imported", TargetType: &target, TargetID: &targetID, Metadata: metadata}); e != nil {
			return e
		}
		found = true
		created = true
		return nil
	})
	if err == nil && created {
		s.PushOrg(ctx, org)
	}
	return
}

// Empty private_jwk changes only enablement; it never overwrites credentials.
func (s *Service) setOktaEnabled(ctx context.Context, org uuid.UUID, in idpsyncspec.ConfigInput) (out idpsyncspec.ConfigView, err error) {
	if in.SSOConnectionID == nil {
		return out, apierr.BadRequest("invalid_okta_credentials", "select the configured Okta connection")
	}
	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		c, e := q.LockSSOConnection(ctx, *in.SSOConnectionID)
		if e != nil {
			return e
		}
		if c.OrgID != org {
			return apierr.NotFound("idp_sync_not_configured", "directory not configured")
		}
		if in.Enabled && !oktaConnectionMatches(c, org, in.OktaOrgURL) {
			return apierr.BadRequest("invalid_okta_connection", "the Okta connection must be tested and enabled")
		}
		row, e := q.SetOktaDirectoryEnabled(ctx, sqlc.SetOktaDirectoryEnabledParams{OrgID: org, SsoConnectionID: pgtype.UUID{Bytes: *in.SSOConnectionID, Valid: true}, Enabled: in.Enabled, ClientID: in.ClientID, OktaOrgUrl: &in.OktaOrgURL})
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.New(409, "directory_namespace_locked", "reload the configured directory before changing sync state")
		}
		if e != nil {
			return e
		}
		out = s.viewOf(row)
		return s.humanAudit(ctx, q, org, "idp_sync.activation_changed", "idp_sync_config", "okta", map[string]any{"enabled": in.Enabled})
	})
	return
}
