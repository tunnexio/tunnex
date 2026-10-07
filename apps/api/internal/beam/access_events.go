package beam

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// AccessEvent projects retained admission evidence. It never reads origin
// targets, request content, browser tokens or live connector credentials.
type AccessEvent struct {
	ID        uuid.UUID
	ShareID   uuid.UUID
	UserID    *uuid.UUID
	Action    string
	Reason    string
	CreatedAt time.Time
}

func (s *Service) AccessEvents(ctx context.Context, org uuid.UUID, a Actor, user, share *uuid.UUID, deniesOnly bool, before time.Time, beforeID uuid.UUID, limit int) ([]AccessEvent, error) {
	if s.pool == nil {
		return nil, unavailable()
	}
	if a.SessionID == "" || a.CredentialID != uuid.Nil {
		return nil, deny()
	}
	if e := s.member(ctx, s.pool, org, a.ID, rbac.PermBeamAuditView); e != nil {
		return nil, e
	}
	if limit < 1 || limit > 200 {
		return nil, invalid("Invalid access-event page limit")
	}
	rows, e := s.pool.Query(ctx, `SELECT id,target_id,actor_user_id,action,COALESCE(metadata->>'reason',''),created_at FROM audit_logs WHERE org_id=$1 AND target_type='beam_share' AND action IN ('beam.access.allowed','beam.access.denied') AND (created_at,id)<($2,$3) AND ($4::uuid IS NULL OR actor_user_id=$4) AND ($5::uuid IS NULL OR target_id=$5::text) AND (NOT $6 OR action='beam.access.denied') ORDER BY created_at DESC,id DESC LIMIT $7`, org, before, beforeID, user, share, deniesOnly, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []AccessEvent{}
	for rows.Next() {
		var v AccessEvent
		var target string
		if e = rows.Scan(&v.ID, &target, &v.UserID, &v.Action, &v.Reason, &v.CreatedAt); e != nil {
			return nil, e
		}
		v.ShareID, e = uuid.Parse(target)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
