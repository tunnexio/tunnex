package beam

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"time"
)

type PolicyImpact struct {
	PolicyVersion                int64 `json:"policy_version"`
	ActiveShareCount             int   `json:"active_share_count"`
	AffectedShareCount           int   `json:"affected_share_count"`
	AffectedReviewerSessionCount int   `json:"affected_reviewer_session_count"`
	RequiresConfirmation         bool  `json:"requires_confirmation"`
}
type GrantsImpact struct {
	ShareVersion                 int64 `json:"share_version"`
	RemovedGrantCount            int   `json:"removed_grant_count"`
	AffectedReviewerCount        int   `json:"affected_reviewer_count"`
	AffectedReviewerSessionCount int   `json:"affected_reviewer_session_count"`
	RequiresConfirmation         bool  `json:"requires_confirmation"`
}

func confirmation(msg string) error { return apierr.Conflict("beam_impact_confirmation_required", msg) }
func (s *Service) preparePolicy(ctx context.Context, org uuid.UUID, a Actor, in PolicyInput) (pgx.Tx, Policy, error) {
	if !a.ManagePolicy {
		return nil, Policy{}, deny()
	}
	if in.ExpectedVersion < 1 || in.MaxDuration < 60 || in.MaxDuration > 86400 || in.MaxShares < 1 || in.MaxShares > 25 || len(in.PublisherGroups) > 100 || len(in.ReviewerGroups) > 100 || len(in.ReviewerUsers) > 100 {
		return nil, Policy{}, invalid("Invalid policy limits")
	}
	tx, e := s.transaction(ctx, org)
	if e != nil {
		return nil, Policy{}, e
	}
	ok := false
	defer func() {
		if !ok {
			_ = tx.Rollback(ctx)
		}
	}()
	if e = s.member(ctx, tx, org, a.ID, rbac.PermBeamPolicyManage); e != nil {
		return nil, Policy{}, e
	}
	p, e := s.policy(ctx, tx, org)
	if e != nil {
		return nil, p, e
	}
	if in.Enabled && !p.DomainReady {
		return nil, p, invalid("Configure and verify the installation Beam domain before enabling organization policy")
	}
	if p.Version != in.ExpectedVersion {
		return nil, p, conflict()
	}
	if in.Enabled && !nextPolicy(p, in).OpenForAllUsers && len(in.PublisherGroups) == 0 {
		return nil, p, invalid("Select at least one publisher group or open Beam for all users")
	}
	for _, ids := range [][]uuid.UUID{in.PublisherGroups, in.ReviewerGroups} {
		for _, id := range ids {
			var ok bool
			e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_groups WHERE org_id=$1 AND id=$2)`, org, id).Scan(&ok)
			if e != nil {
				return nil, p, e
			}
			if !ok {
				return nil, p, invalid("Policy group is outside this organization")
			}
		}
	}
	for _, id := range in.ReviewerUsers {
		var ok bool
		e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM memberships WHERE org_id=$1 AND user_id=$2)`, org, id).Scan(&ok)
		if e != nil {
			return nil, p, e
		}
		if !ok {
			return nil, p, invalid("Policy user is outside this organization")
		}
	}
	ok = true
	return tx, p, nil
}
func (s *Service) PreviewPolicy(ctx context.Context, org uuid.UUID, a Actor, in PolicyInput) (PolicyImpact, error) {
	tx, p, e := s.preparePolicy(ctx, org, a, in)
	if e != nil {
		return PolicyImpact{}, e
	}
	defer tx.Rollback(ctx)
	return s.policyImpact(ctx, tx, org, p, in)
}
func nextPolicy(p Policy, in PolicyInput) Policy {
	p.Enabled = in.Enabled
	if in.OpenForAllUsers != nil {
		p.OpenForAllUsers = *in.OpenForAllUsers
	}
	p.PublisherGroups = in.PublisherGroups
	p.ReviewerUsers = in.ReviewerUsers
	p.ReviewerGroups = in.ReviewerGroups
	p.MaxDuration = in.MaxDuration
	p.MaxShares = in.MaxShares
	p.RequireMFA = in.RequireMFA
	return p
}

// Count current live browser sessions, rather than streams, so HTTP assets do not inflate the warning.
func (s *Service) policyImpact(ctx context.Context, q reader, org uuid.UUID, p Policy, in PolicyInput) (PolicyImpact, error) {
	out := PolicyImpact{PolicyVersion: p.Version}
	next := nextPolicy(p, in)
	rows, e := q.Query(ctx, `SELECT `+shareColumns+` FROM beam_shares WHERE org_id=$1 AND state IN ('starting','active','paused') AND expires_at>now()`, org)
	if e != nil {
		return out, e
	}
	shares := []Share{}
	for rows.Next() {
		r, e := scanShare(rows)
		if e != nil {
			rows.Close()
			return out, e
		}
		shares = append(shares, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	for _, r := range shares {
		out.ActiveShareCount++
		publisherWithdrawn := s.publisher(ctx, q, org, r.PublisherID, next) != nil
		lifetimeReduced := r.ExpiresAt.After(r.CreatedAt.Add(time.Duration(next.MaxDuration) * time.Second))
		affected := publisherWithdrawn || lifetimeReduced || (!p.RequireMFA && next.RequireMFA)
		sessions, e := s.liveReviewerSessions(ctx, q, r)
		if e != nil {
			return out, e
		}
		for _, v := range sessions {
			if publisherWithdrawn || lifetimeReduced || s.reviewer(ctx, q, r, v.user, next) != nil {
				out.AffectedReviewerSessionCount++
				affected = true
				continue
			}
			if _, e = s.parent(ctx, q, org, v.user, v.parent, next.RequireMFA); e != nil {
				out.AffectedReviewerSessionCount++
				affected = true
			}
		}
		if affected {
			out.AffectedShareCount++
		}
	}
	out.RequiresConfirmation = out.AffectedShareCount > 0 || (out.ActiveShareCount > 0 && in.MaxShares < p.MaxShares)
	return out, nil
}

type reviewerSession struct {
	user   uuid.UUID
	parent string
}

func (s *Service) liveReviewerSessions(ctx context.Context, q reader, r Share) ([]reviewerSession, error) {
	rows, e := q.Query(ctx, `SELECT DISTINCT b.user_id,b.parent_session_id FROM beam_browser_sessions b WHERE b.org_id=$1 AND b.share_id=$2 AND b.expires_at>now() AND EXISTS(SELECT 1 FROM beam_streams t WHERE t.org_id=b.org_id AND t.share_id=b.share_id AND t.token_hash=b.token_hash AND t.expires_at>now())`, r.OrgID, r.ID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []reviewerSession{}
	for rows.Next() {
		var v reviewerSession
		if e = rows.Scan(&v.user, &v.parent); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Service) grantsImpact(ctx context.Context, q reader, r Share, p Policy, in GrantsInput) (GrantsImpact, error) {
	out := GrantsImpact{ShareVersion: r.Version}
	kept := map[Grant]bool{}
	for _, g := range in.Grants {
		kept[g] = true
	}
	rows, e := q.Query(ctx, `SELECT subject_kind,subject_id FROM beam_grants WHERE org_id=$1 AND share_id=$2`, r.OrgID, r.ID)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var g Grant
		if e = rows.Scan(&g.SubjectKind, &g.SubjectID); e != nil {
			rows.Close()
			return out, e
		}
		if !kept[g] {
			out.RemovedGrantCount++
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	sessions, e := s.liveReviewerSessions(ctx, q, r)
	if e != nil {
		return out, e
	}
	userIDs, groupIDs := []uuid.UUID{}, []uuid.UUID{}
	for _, g := range in.Grants {
		if g.SubjectKind == "user" {
			userIDs = append(userIDs, g.SubjectID)
		} else {
			groupIDs = append(groupIDs, g.SubjectID)
		}
	}
	e = q.QueryRow(ctx, `SELECT count(DISTINCT m.user_id) FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=$1 AND u.status='active' AND u.deleted_at IS NULL AND EXISTS(SELECT 1 FROM beam_grants g WHERE g.org_id=$1 AND g.share_id=$2 AND ((g.subject_kind='user' AND g.subject_id=m.user_id AND ($8 OR m.user_id=$3 OR m.user_id=ANY($4::uuid[]))) OR (g.subject_kind='group' AND ($8 OR g.subject_id=ANY($5::uuid[])) AND EXISTS(SELECT 1 FROM group_members gm WHERE gm.org_id=$1 AND gm.group_id=g.subject_id AND gm.user_id=m.user_id)))) AND NOT(m.user_id=ANY($6::uuid[]) OR EXISTS(SELECT 1 FROM group_members gm WHERE gm.org_id=$1 AND gm.user_id=m.user_id AND gm.group_id=ANY($7::uuid[])))`, r.OrgID, r.ID, r.PublisherID, p.ReviewerUsers, p.ReviewerGroups, userIDs, groupIDs, p.OpenForAllUsers).Scan(&out.AffectedReviewerCount)
	if e != nil {
		return out, e
	}
	for _, v := range sessions {
		allowed := false
		for _, g := range in.Grants {
			if g.SubjectKind == "user" && g.SubjectID == v.user {
				allowed = true
				break
			}
			if g.SubjectKind == "group" {
				var member bool
				e = q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM group_members WHERE org_id=$1 AND group_id=$2 AND user_id=$3)`, r.OrgID, g.SubjectID, v.user).Scan(&member)
				if e != nil {
					return out, e
				}
				if member {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			out.AffectedReviewerSessionCount++
		}
	}
	out.RequiresConfirmation = out.RemovedGrantCount > 0
	return out, nil
}
func (s *Service) PreviewGrants(ctx context.Context, org, id uuid.UUID, a Actor, in GrantsInput) (GrantsImpact, error) {
	tx, e := s.transaction(ctx, org)
	if e != nil {
		return GrantsImpact{}, e
	}
	defer tx.Rollback(ctx)
	r, e := scanShare(tx.QueryRow(ctx, `SELECT `+shareColumns+` FROM beam_shares WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id))
	if e != nil || r.PublisherID != a.ID && !a.ManageAll {
		return GrantsImpact{}, missing()
	}
	perm := rbac.PermBeamManageOwn
	if r.PublisherID != a.ID {
		perm = rbac.PermBeamManageAll
	}
	if e = s.member(ctx, tx, org, a.ID, perm); e != nil {
		return GrantsImpact{}, e
	}
	if r.Version != in.ExpectedVersion {
		return GrantsImpact{}, conflict()
	}
	p, e := s.policy(ctx, tx, org)
	if e != nil {
		return GrantsImpact{}, e
	}
	if _, e = s.source(ctx, tx, r, p); e != nil {
		return GrantsImpact{}, e
	}
	if e = s.validateSubjects(ctx, tx, org, r.PublisherID, p, in.Grants); e != nil {
		return GrantsImpact{}, e
	}
	return s.grantsImpact(ctx, tx, r, p, in)
}
