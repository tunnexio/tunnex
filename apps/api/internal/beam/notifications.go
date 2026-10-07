package beam

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Notification struct {
	ID        string     `json:"id"`
	Kind      string     `json:"kind"`
	ShareID   uuid.UUID  `json:"share_id"`
	ProjectID *uuid.UUID `json:"project_id,omitempty"`
	Title     string     `json:"title"`
	CreatedAt time.Time  `json:"created_at"`
}

// Notifications are a bounded current-access feed, not persisted outbound deliveries.
// Expiry reminders are computed at read time; terminal/revoked reviewer access disappears.
func (s *Service) Notifications(ctx context.Context, org uuid.UUID, a Actor, limit, offset int) (Page[Notification], error) {
	out := Page[Notification]{Items: []Notification{}, Limit: limit, Offset: offset, ServerTime: time.Now()}
	p, e := s.policy(ctx, s.pool, org)
	if e != nil {
		return out, e
	}
	if a.CredentialID != uuid.Nil {
		return out, deny()
	}
	if _, e = s.parent(ctx, s.pool, org, a.ID, a.SessionID, p.RequireMFA); e != nil {
		return out, e
	}
	owner, e := s.ListQueryScope(ctx, org, a, false, 100, 0, "", "", "", "active")
	if e != nil {
		return out, e
	}
	shared, e := s.ListQueryScope(ctx, org, a, true, 100, 0, "", "", "", "active")
	if e != nil {
		return out, e
	}
	seen := map[uuid.UUID]bool{}
	notifications := []Notification{}
	for _, r := range append(owner.Items, shared.Items...) {
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		if _, e = s.feedbackAuthority(ctx, s.pool, org, r.ID, a, false); e != nil {
			continue
		}
		if r.CanOpen {
			notifications = append(notifications, Notification{ID: r.ID.String() + ":ready", Kind: "preview_ready", ShareID: r.ID, ProjectID: r.ProjectID, Title: r.Name + " is ready to review", CreatedAt: r.CreatedAt})
		}
		if r.ExpiresAt.After(out.ServerTime) && r.ExpiresAt.Before(out.ServerTime.Add(10*time.Minute)) {
			notifications = append(notifications, Notification{ID: r.ID.String() + ":expiry", Kind: "expiring", ShareID: r.ID, ProjectID: r.ProjectID, Title: r.Name + " expires soon", CreatedAt: r.ExpiresAt.Add(-10 * time.Minute)})
		}
		var id uuid.UUID
		var created time.Time
		e = s.pool.QueryRow(ctx, `SELECT id,created_at FROM beam_feedback WHERE org_id=$1 AND share_id=$2 AND author_id<>$3 ORDER BY created_at DESC,id LIMIT 1`, org, r.ID, a.ID).Scan(&id, &created)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return out, e
		}
		if e == nil {
			notifications = append(notifications, Notification{ID: id.String(), Kind: "feedback", ShareID: r.ID, ProjectID: r.ProjectID, Title: "New feedback on " + r.Name, CreatedAt: created})
		}
	}
	sort.Slice(notifications, func(i, j int) bool {
		if notifications[i].CreatedAt.Equal(notifications[j].CreatedAt) {
			return notifications[i].ID < notifications[j].ID
		}
		return notifications[i].CreatedAt.After(notifications[j].CreatedAt)
	})
	if offset < len(notifications) {
		end := offset + limit
		if end > len(notifications) {
			end = len(notifications)
		}
		out.Items = notifications[offset:end]
	}
	return out, nil
}
