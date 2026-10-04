package appaccess

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"time"
)

type AdminAppSession struct {
	ID, AppID, UserID, InstallationGeneration uuid.UUID
	Label                                     string
	CreatedAt, ExpiresAt                      time.Time
}

func (s *Service) ApplicationSessions(ctx context.Context, org, app uuid.UUID, limit, offset int32) ([]AdminAppSession, error) {
	out := []AdminAppSession{}
	if limit < 1 || limit > 100 || offset < 0 || offset > 10000 {
		return nil, apierr.BadRequest("invalid_pagination", "invalid session pagination")
	}
	if _, err := s.GetApplication(ctx, org, app); err != nil {
		return nil, err
	}
	if !s.sessionReady() {
		return nil, appInfrastructureUnavailable()
	}
	generation, err := s.installationGeneration(ctx)
	if err != nil {
		return nil, err
	}
	key := "aa:session-app:" + generation.String() + ":" + org.String() + ":" + app.String()
	ids, err := s.sessionAuthority.apps.rdb.ZRange(ctx, key, int64(offset), int64(offset+limit-1)).Result()
	if err != nil {
		return nil, appInfrastructureUnavailable()
	}
	q := sqlc.New(s.pool)
	for _, raw := range ids {
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, appInfrastructureUnavailable()
		}
		r, err := s.sessionAuthority.apps.RecordByID(ctx, id)
		if errors.Is(err, ErrAppSessionMissing) {
			continue
		}
		if err != nil {
			return nil, appInfrastructureUnavailable()
		}
		if r.Binding.OrgID != org || r.Binding.AppID != app || r.InstallationGeneration != generation {
			continue
		}
		revoked, err := q.AppAccessSessionRevoked(ctx, sqlc.AppAccessSessionRevokedParams{OrgID: org, AppID: app, UserID: r.UserID, SessionID: id, InstallationGeneration: generation})
		if err != nil {
			return nil, appInfrastructureUnavailable()
		}
		if revoked {
			continue
		}
		out = append(out, AdminAppSession{ID: id, AppID: app, UserID: r.UserID, InstallationGeneration: generation, Label: r.Label, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt})
	}
	return out, nil
}
func (s *Service) RevokeApplicationSession(ctx context.Context, org, app, actor, id uuid.UUID) error {
	if _, err := s.GetApplication(ctx, org, app); err != nil {
		return err
	}
	if !s.sessionReady() {
		return appInfrastructureUnavailable()
	}
	q := sqlc.New(s.pool)
	_, err := q.GetAppAccessSessionRevocationForApplication(ctx, sqlc.GetAppAccessSessionRevocationForApplicationParams{OrgID: org, AppID: app, SessionID: id})
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return appInfrastructureUnavailable()
	}
	r, err := s.sessionAuthority.apps.RecordByID(ctx, id)
	if errors.Is(err, ErrAppSessionMissing) {
		_, retry := q.GetAppAccessSessionRevocationForApplication(ctx, sqlc.GetAppAccessSessionRevocationForApplicationParams{OrgID: org, AppID: app, SessionID: id})
		if retry == nil {
			return nil
		}
		if !errors.Is(retry, pgx.ErrNoRows) {
			return appInfrastructureUnavailable()
		}
		return apierr.NotFound("app_session_unavailable", "app session unavailable")
	}
	if err != nil {
		return appInfrastructureUnavailable()
	}
	if r.Binding.OrgID != org || r.Binding.AppID != app || r.InstallationGeneration == uuid.Nil {
		return apierr.NotFound("app_session_unavailable", "app session unavailable")
	}
	newRevocation := false
	err = s.transaction(ctx, func(q *sqlc.Queries) error {
		live := pgtype.UUID{}
		if _, e := q.GetUserByID(ctx, r.UserID); e == nil {
			live = eventUUID(r.UserID)
		} else if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		inserted, e := q.TryInsertAppAccessSessionRevocation(ctx, sqlc.TryInsertAppAccessSessionRevocationParams{OrgID: org, AppID: app, UserID: r.UserID, SessionID: id, InstallationGeneration: r.InstallationGeneration, LiveUserID: live, AbsoluteExpiresAt: r.ExpiresAt, ActorUserID: eventUUID(actor), ActorUserSnapshot: eventUUID(actor), Reason: "admin"})
		if e != nil || inserted == 0 {
			return e
		}
		newRevocation = true
		return audit(ctx, q, org, actor, id.String(), "app_access.session_revoked", 1)
	})
	if err != nil {
		return appInfrastructureUnavailable()
	}
	_ = s.sessionAuthority.apps.RevokeOwn(ctx, org, r.UserID, id)
	if newRevocation {
		s.emit(sessionEvent(r, uuid.Nil, uuid.Nil, "session_revoked", "revoked", "admin"))
	}
	return nil
}
