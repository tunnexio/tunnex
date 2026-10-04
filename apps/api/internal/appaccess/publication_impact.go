package appaccess

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"sort"
	"time"
)

type PublicationImpact struct {
	EvaluatedAt                                                                            time.Time
	ApplicationVersion, AuthorityVersion, MatchingUserCount, LiveAppSessionCount           int64
	MatchingUserCountIsLowerBound, LiveAppSessionCountIsLowerBound, SessionImpactAvailable bool
}

func (s *Service) PublicationImpact(ctx context.Context, org, app uuid.UUID) (PublicationImpact, error) {
	out := PublicationImpact{EvaluatedAt: s.now()}
	state, err := s.GetPublication(ctx, org, app)
	if err != nil {
		return out, err
	}
	out.ApplicationVersion = state.ApplicationVersion
	if state.Active != nil {
		out.AuthorityVersion = state.Active.AuthorityVersion
	}
	roles := []string{}
	for role := range rbac.Policy() {
		if rbac.CanAny([]string{role}, rbac.PermAppAccessUse) {
			roles = append(roles, role)
		}
	}
	sort.Strings(roles)
	q := sqlc.New(s.pool)
	count, err := q.AppAccessPublicationMatchingUserCount(ctx, sqlc.AppAccessPublicationMatchingUserCountParams{OrgID: org, AppID: app, EligibleRoles: roles, EvaluatedAt: out.EvaluatedAt})
	if err != nil {
		return out, appInfrastructureUnavailable()
	}
	out.MatchingUserCount = count
	if count > 1000 {
		out.MatchingUserCount = 1000
		out.MatchingUserCountIsLowerBound = true
	}
	if !s.sessionReady() {
		return out, nil
	}
	generation, err := s.installationGeneration(ctx)
	if err != nil {
		return out, err
	}
	key := "aa:session-app:" + generation.String() + ":" + org.String() + ":" + app.String()
	ids, err := s.sessionAuthority.apps.rdb.ZRange(ctx, key, 0, 1000).Result()
	if err != nil {
		return out, nil
	} // Session telemetry unavailable must not prevent withdrawal.
	out.SessionImpactAvailable = true
	if len(ids) > 1000 {
		out.LiveAppSessionCountIsLowerBound = true
		ids = ids[:1000]
	}
	for _, raw := range ids {
		id, err := uuid.Parse(raw)
		if err != nil {
			out.SessionImpactAvailable = false
			return out, nil
		}
		r, err := s.sessionAuthority.apps.RecordByID(ctx, id)
		if errors.Is(err, ErrAppSessionMissing) || errors.Is(err, redis.Nil) {
			continue
		}
		if err != nil {
			out.SessionImpactAvailable = false
			return out, nil
		}
		if r.Binding.OrgID != org || r.Binding.AppID != app || r.InstallationGeneration != generation {
			continue
		}
		revoked, err := q.AppAccessSessionRevoked(ctx, sqlc.AppAccessSessionRevokedParams{OrgID: org, AppID: app, UserID: r.UserID, SessionID: id, InstallationGeneration: generation})
		if err != nil {
			out.SessionImpactAvailable = false
			return out, nil
		}
		if !revoked {
			out.LiveAppSessionCount++
		}
	}
	return out, nil
}
