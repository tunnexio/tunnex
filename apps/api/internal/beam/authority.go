package beam

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"strings"
	"time"
)

func (s *Service) policy(ctx context.Context, q reader, org uuid.UUID) (Policy, error) {
	installation, e := s.installation(ctx, q)
	if e != nil {
		return Policy{}, e
	}
	p := Policy{Capabilities: []string{"path_routes_v1", "saved_projects_v1"}, Version: 1, MaxDuration: 86400, MaxShares: 5, PublisherGroups: []uuid.UUID{}, ReviewerUsers: []uuid.UUID{}, ReviewerGroups: []uuid.UUID{}, BaseDomain: installation.base, DomainReady: s.installationReady(installation), ProtocolVersion: 1, MinClientVersion: "0.1.7", domainProxyURL: installation.proxy}
	if installation.expires != nil {
		p.domainReadyUntil = *installation.expires
	}
	e = q.QueryRow(ctx, `SELECT enabled,version,publisher_group_ids,reviewer_user_ids,reviewer_group_ids,max_duration_seconds,max_shares,require_mfa,open_for_all_users FROM beam_policies WHERE org_id=$1`, org).Scan(&p.Enabled, &p.Version, &p.PublisherGroups, &p.ReviewerUsers, &p.ReviewerGroups, &p.MaxDuration, &p.MaxShares, &p.RequireMFA, &p.OpenForAllUsers)
	if errors.Is(e, pgx.ErrNoRows) {
		return p, nil
	}
	return p, e
}
func (s *Service) member(ctx context.Context, q reader, org, user uuid.UUID, perm rbac.Permission) error {
	var roles []string
	var active bool
	e := q.QueryRow(ctx, `SELECT m.roles,u.status='active' AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND NOT u.must_change_password AND o.deleted_at IS NULL FROM memberships m JOIN users u ON u.id=m.user_id JOIN organizations o ON o.id=m.org_id WHERE m.org_id=$1 AND m.user_id=$2`, org, user).Scan(&roles, &active)
	if e != nil || !active || !rbac.CanAny(roles, perm) {
		return deny()
	}
	return nil
}
func (s *Service) publisher(ctx context.Context, q reader, org, user uuid.UUID, p Policy) error {
	if !p.Enabled || !p.DomainReady {
		return unavailable()
	}
	if e := s.member(ctx, q, org, user, rbac.PermBeamCreate); e != nil {
		return e
	}
	if p.OpenForAllUsers {
		return nil
	}
	var allowed bool
	e := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM group_members WHERE org_id=$1 AND user_id=$2 AND group_id=ANY($3::uuid[]))`, org, user, p.PublisherGroups).Scan(&allowed)
	if e != nil {
		return e
	}
	if !allowed {
		return apierr.Forbidden("beam_publisher_denied", "Your account is not in a permitted publisher group")
	}
	return nil
}
func (s *Service) GetPolicy(ctx context.Context, org uuid.UUID, a Actor) (Policy, error) {
	p, e := s.policy(ctx, s.pool, org)
	if e != nil {
		return p, e
	}
	p.CanManagePolicy = a.ManagePolicy
	p.CanPublish = s.publisher(ctx, s.pool, org, a.ID, p) == nil
	return p, nil
}
func (s *Service) parent(ctx context.Context, q reader, org, user uuid.UUID, id string, requireMFA bool) (time.Time, error) {
	if s.sessions == nil || id == "" {
		return time.Time{}, deny()
	}
	sess, deadline, e := s.sessions.GetNoTouch(ctx, id)
	if e != nil || sess.UserID != user || (sess.AuthMethod != "local_password" && sess.AuthMethod != "sso") {
		return time.Time{}, deny()
	}
	var epoch int64
	var revoked bool
	e = q.QueryRow(ctx, `SELECT u.app_auth_epoch,EXISTS(SELECT 1 FROM app_access_parent_logout_tombstones WHERE parent_hash=$2) FROM users u WHERE u.id=$1`, user, hash(id)).Scan(&epoch, &revoked)
	if e != nil || revoked || (sess.AppAuthEpoch == 0 && epoch != 1) || (sess.AppAuthEpoch > 0 && sess.AppAuthEpoch != epoch) {
		return time.Time{}, deny()
	}
	if e = s.member(ctx, q, org, user, rbac.PermBeamUse); e != nil {
		return time.Time{}, e
	}
	if requireMFA && (!session.ValidMFAAssurance(sess.MFAVerifiedAt, sess.MFAAssuranceSource, time.Now()) || sess.MFAVerifiedAt.Before(time.Now().Add(-5*time.Minute))) {
		return time.Time{}, apierr.Forbidden("mfa_step_up_required", "Verify MFA to open this Beam share")
	}
	return deadline, nil
}
func (s *Service) source(ctx context.Context, q reader, r Share, p Policy) (time.Time, error) {
	label := strings.TrimSuffix(r.Hostname, "."+p.BaseDomain)
	if len(r.Hostname) != 35+len(p.BaseDomain) || len(label) != 34 || !strings.HasPrefix(label, "p-") {
		return time.Time{}, deny()
	}
	if b, e := hex.DecodeString(label[2:]); e != nil || len(b) != 16 {
		return time.Time{}, deny()
	}
	if e := s.publisher(ctx, q, r.OrgID, r.PublisherID, p); e != nil {
		return time.Time{}, e
	}
	deadline := r.CreatedAt.Add(time.Duration(p.MaxDuration) * time.Second)
	if p.domainReadyUntil.Before(deadline) {
		deadline = p.domainReadyUntil
	}
	if r.ExpiresAt.Before(deadline) {
		deadline = r.ExpiresAt
	}
	if r.SourceCredentialID != nil {
		var until time.Time
		e := q.QueryRow(ctx, `SELECT expires_at FROM cli_credentials WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()`, *r.SourceCredentialID, r.PublisherID).Scan(&until)
		if e != nil {
			return time.Time{}, deny()
		}
		if until.Before(deadline) {
			deadline = until
		}
	} else {
		until, e := s.parent(ctx, q, r.OrgID, r.PublisherID, r.SourceSessionID, false)
		if e != nil {
			return time.Time{}, e
		}
		if until.Before(deadline) {
			deadline = until
		}
	}
	if !deadline.After(time.Now()) || terminal(r.State) {
		return time.Time{}, deny()
	}
	return deadline, nil
}
func (s *Service) reviewer(ctx context.Context, q reader, r Share, user uuid.UUID, p Policy) error {
	if e := s.member(ctx, q, r.OrgID, user, rbac.PermBeamUse); e != nil {
		return e
	}
	var ok bool
	e := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM beam_grants g WHERE g.org_id=$1 AND g.share_id=$2 AND ((g.subject_kind='user' AND g.subject_id=$3 AND ($7 OR g.subject_id=$4 OR g.subject_id=ANY($5::uuid[]))) OR (g.subject_kind='group' AND ($7 OR g.subject_id=ANY($6::uuid[])) AND EXISTS(SELECT 1 FROM group_members m WHERE m.org_id=$1 AND m.group_id=g.subject_id AND m.user_id=$3))))`, r.OrgID, r.ID, user, r.PublisherID, p.ReviewerUsers, p.ReviewerGroups, p.OpenForAllUsers).Scan(&ok)
	if e != nil {
		return e
	}
	if !ok {
		return deny()
	}
	return nil
}
func (s *Service) current(ctx context.Context, q reader, b Binding) (Share, Policy, time.Time, error) {
	r, e := scanShare(q.QueryRow(ctx, `SELECT `+shareColumns+` FROM beam_shares WHERE org_id=$1 AND id=$2`, b.OrgID, b.AppID))
	if e != nil {
		return r, Policy{}, time.Time{}, deny()
	}
	if r.Binding() != b {
		return r, Policy{}, time.Time{}, deny()
	}
	p, e := s.policy(ctx, q, r.OrgID)
	if e != nil {
		return r, p, time.Time{}, e
	}
	deadline, e := s.source(ctx, q, r, p)
	if e != nil || r.State == "paused" {
		return r, p, time.Time{}, deny()
	}
	return r, p, deadline, nil
}
func capLease(until time.Time) time.Time { return capLeaseAt(until, time.Now()) }
func capLeaseAt(until, start time.Time) time.Time {
	limit := start.Add(4 * time.Second)
	if until.Before(limit) {
		return until
	}
	return limit
}
func (s *Service) Channel(ctx context.Context, b Binding, serial string) (time.Time, error) {
	started := time.Now()
	r, _, deadline, e := s.current(ctx, s.pool, b)
	if e != nil || r.Serial == nil || canonicalSerial(serial) == "" || canonicalSerial(*r.Serial) != canonicalSerial(serial) {
		return time.Time{}, deny()
	}
	tag, e := s.pool.Exec(ctx, `UPDATE beam_shares SET last_channel_at=now() WHERE org_id=$1 AND id=$2 AND generation=$3 AND certificate_serial=$4 AND state IN ('starting','active') AND expires_at>now()`, b.OrgID, b.AppID, b.Generation, *r.Serial)
	if e != nil || tag.RowsAffected() != 1 {
		return time.Time{}, deny()
	}
	if !capLeaseAt(deadline, started).After(time.Now()) {
		return time.Time{}, deny()
	}
	return capLeaseAt(deadline, started), nil
}
func (s *Service) Resolve(ctx context.Context, hostname string) (Binding, error) {
	r, e := scanShare(s.pool.QueryRow(ctx, `SELECT `+shareColumns+` FROM beam_shares WHERE hostname=$1`, hostname))
	if e != nil {
		return Binding{}, missing()
	}
	_, _, _, e = s.current(ctx, s.pool, r.Binding())
	return r.Binding(), e
}
func (s *Service) Credential(ctx context.Context, user uuid.UUID, raw string) (uuid.UUID, error) {
	var id uuid.UUID
	e := s.pool.QueryRow(ctx, `SELECT id FROM cli_credentials WHERE user_id=$1 AND token_hash=$2 AND revoked_at IS NULL AND expires_at>now()`, user, hash(raw)).Scan(&id)
	if e != nil {
		return uuid.Nil, deny()
	}
	return id, nil
}
func nonceHash(raw string) ([]byte, error) {
	b, e := hex.DecodeString(raw)
	if e != nil || len(b) != 32 {
		return nil, invalid("Invalid launch nonce")
	}
	return b, nil
}
