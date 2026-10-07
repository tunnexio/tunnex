package beam

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"strings"
	"time"
	"unicode/utf8"
)

type EventFilter struct {
	Search, Action, Outcome string
	ShareID                 uuid.UUID
}

func validateSearch(v string) error {
	if !utf8.ValidString(v) || utf8.RuneCountInString(v) > 200 || strings.ContainsAny(v, "\r\n\x00") {
		return invalid("Search must contain at most 200 characters")
	}
	return nil
}
func (s *Service) EventsFiltered(ctx context.Context, org uuid.UUID, limit, offset int, f EventFilter) (Page[Event], error) {
	out := Page[Event]{Items: []Event{}, Limit: limit, Offset: offset, ServerTime: time.Now()}
	if s.pool == nil {
		return out, unavailable()
	}
	for _, v := range []string{f.Search, f.Action, f.Outcome} {
		if e := validateSearch(v); e != nil {
			return out, e
		}
	}
	if len(f.Action) > 100 || len(f.Outcome) > 30 {
		return out, invalid("Invalid event filter")
	}
	rows, e := s.pool.Query(ctx, `SELECT id,target_id,action,COALESCE(metadata->>'outcome','success'),COALESCE(metadata->>'reason',''),actor_user_id,created_at FROM audit_logs WHERE org_id=$1 AND action LIKE 'beam.%' AND ($4='' OR position(lower($4) in lower(action))>0 OR position(lower($4) in lower(COALESCE(metadata->>'reason','')))>0) AND ($5='' OR action=$5) AND ($6='' OR COALESCE(metadata->>'outcome','success')=$6) AND ($7='' OR (target_type='beam_share' AND target_id=$7)) ORDER BY created_at DESC,id LIMIT $2 OFFSET $3`, org, limit, offset, f.Search, f.Action, f.Outcome, filterID(f.ShareID))
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var v Event
		if e = rows.Scan(&v.ID, &v.ShareID, &v.Action, &v.Outcome, &v.Reason, &v.ActorID, &v.CreatedAt); e != nil {
			return out, e
		}
		out.Items = append(out.Items, v)
	}
	return out, rows.Err()
}
func filterID(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}
func (s *Service) managedShare(ctx context.Context, org, id uuid.UUID, a Actor) (Share, error) {
	if s.pool == nil {
		return Share{}, unavailable()
	}
	r, e := scanShare(s.pool.QueryRow(ctx, `SELECT `+shareColumns+` FROM beam_shares WHERE org_id=$1 AND id=$2`, org, id))
	if e != nil || r.PublisherID != a.ID && !a.ManageAll {
		return Share{}, missing()
	}
	perm := rbac.PermBeamManageOwn
	if r.PublisherID != a.ID {
		perm = rbac.PermBeamManageAll
	}
	if e = s.member(ctx, s.pool, org, a.ID, perm); e != nil {
		return Share{}, e
	}
	return r, nil
}
func (s *Service) ShareEvents(ctx context.Context, org, id uuid.UUID, a Actor, limit, offset int, f EventFilter) (Page[Event], error) {
	if _, e := s.managedShare(ctx, org, id, a); e != nil {
		return Page[Event]{}, e
	}
	f.ShareID = id
	return s.EventsFiltered(ctx, org, limit, offset, f)
}

type Diagnostics struct {
	ShareID          uuid.UUID `json:"share_id"`
	Hostname         string    `json:"hostname"`
	State            string    `json:"state"`
	Connectivity     string    `json:"connectivity"`
	Version          int64     `json:"version"`
	AuthorityVersion int64     `json:"authority_version"`
	Generation       uuid.UUID `json:"generation"`
	ExpiresAt        time.Time `json:"expires_at"`
	DomainReady      bool      `json:"domain_ready"`
	Status           string    `json:"status"`
	Reason           string    `json:"reason"`
}

func (s *Service) Diagnostics(ctx context.Context, org, id uuid.UUID, a Actor) (Diagnostics, error) {
	r, e := s.managedShare(ctx, org, id, a)
	if e != nil {
		return Diagnostics{}, e
	}
	p, e := s.policy(ctx, s.pool, org)
	if e != nil {
		return Diagnostics{}, e
	}
	d := Diagnostics{ShareID: r.ID, Hostname: r.Hostname, State: r.State, Connectivity: r.Connectivity, Version: r.Version, AuthorityVersion: r.AuthorityVersion, Generation: r.Generation, ExpiresAt: r.ExpiresAt, DomainReady: p.DomainReady, Status: "ready", Reason: "ready"}
	switch {
	case terminal(r.State):
		d.Status = "ended"
		d.Reason = "share_ended"
	case !p.DomainReady:
		d.Status = "denied"
		d.Reason = "domain_unavailable"
	default:
		if _, e = s.source(ctx, s.pool, r, p); e != nil {
			d.Status = "denied"
			d.Reason = "publisher_authority_unavailable"
		} else if r.State == "paused" {
			d.Status = "waiting"
			d.Reason = "share_paused"
		} else if r.State != "active" || r.Connectivity != "online" {
			d.Status = "waiting"
			d.Reason = "connector_offline"
		}
	}
	return d, nil
}

func validStateFilter(v string) bool {
	switch v {
	case "", "starting", "active", "paused", "stopped", "expired", "revoked":
		return true
	}
	return false
}
func validConnectivityFilter(v string) bool {
	switch v {
	case "", "online", "offline", "origin_unavailable":
		return true
	}
	return false
}
