package appaccess

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// Event accepts identifiers and closed classifications only. Request strings,
// headers, tokens, origin URLs and diagnostic messages have no representation.
type Event struct {
	OrgID, AppID, InstallationGeneration            uuid.UUID
	UserID, GatewayID, ProxyID, SessionID, StreamID uuid.UUID
	ServingGeneration                               uuid.UUID
	Revision                                        int64
	Kind, Outcome, Reason                           string
}

type EventProducer struct {
	pool                              *pgxpool.Pool
	queue                             chan Event
	stop                              chan struct{}
	done                              chan struct{}
	once                              sync.Once
	emissionMu                        sync.RWMutex
	emitted, dropped, storageFailures atomic.Uint64
	tenantMu                          sync.Mutex
	tenantCounts                      map[uuid.UUID][3]uint64
}

func NewEventProducer(pool *pgxpool.Pool) *EventProducer {
	p := &EventProducer{pool: pool, queue: make(chan Event, 1024), stop: make(chan struct{}), done: make(chan struct{}), tenantCounts: make(map[uuid.UUID][3]uint64)}
	go p.run()
	return p
}
func (p *EventProducer) tenantCount(org uuid.UUID, index int) {
	p.tenantMu.Lock()
	defer p.tenantMu.Unlock()
	v, ok := p.tenantCounts[org]
	if !ok && len(p.tenantCounts) >= 1024 {
		return
	}
	v[index]++
	p.tenantCounts[org] = v
}
func (p *EventProducer) TenantCounts(org uuid.UUID) ([3]uint64, bool) {
	p.tenantMu.Lock()
	defer p.tenantMu.Unlock()
	v, ok := p.tenantCounts[org]
	return v, ok
}
func (p *EventProducer) Close() {
	p.once.Do(func() { p.emissionMu.Lock(); close(p.stop); p.emissionMu.Unlock() })
	<-p.done
}
func (p *EventProducer) Counts() (uint64, uint64, uint64) {
	return p.emitted.Load(), p.dropped.Load(), p.storageFailures.Load()
}

var eventMetricDescriptions = []*prometheus.Desc{
	prometheus.NewDesc("tunnex_app_access_events_emitted_total", "App events durably inserted by this process.", nil, nil),
	prometheus.NewDesc("tunnex_app_access_events_dropped_total", "App events refused by the bounded local telemetry buffer.", nil, nil),
	prometheus.NewDesc("tunnex_app_access_events_storage_failures_total", "App event insert or retention failures.", nil, nil),
}

func (p *EventProducer) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range eventMetricDescriptions {
		ch <- d
	}
}
func (p *EventProducer) Collect(ch chan<- prometheus.Metric) {
	e, d, f := p.Counts()
	for i, v := range []uint64{e, d, f} {
		ch <- prometheus.MustNewConstMetric(eventMetricDescriptions[i], prometheus.CounterValue, float64(v))
	}
}
func validEvent(e Event) bool {
	if e.OrgID == uuid.Nil || e.AppID == uuid.Nil || e.InstallationGeneration == uuid.Nil {
		return false
	}
	switch e.Kind {
	case "launch_created", "session_created", "session_revoked", "request_allowed", "request_denied", "stream_renewed", "stream_denied", "stream_terminated", "publication_changed", "recovery":
	default:
		return false
	}
	switch e.Outcome {
	case "allowed", "denied", "completed", "revoked", "failed":
	default:
		return false
	}
	switch e.Reason {
	case "none", "session_invalid", "parent_unavailable", "user_inactive", "membership_unavailable", "no_use_permission", "no_active_grant", "feature_disabled", "feature_unavailable", "publication_unavailable", "installation_changed", "session_revoked", "lease_expired", "connection_closed", "self", "admin", "recovery", "infrastructure_unavailable":
	default:
		return false
	}
	return true
}
func (p *EventProducer) Emit(e Event) {
	if p == nil {
		return
	}
	p.emissionMu.RLock()
	defer p.emissionMu.RUnlock()
	if !validEvent(e) {
		p.dropped.Add(1)
		p.tenantCount(e.OrgID, 1)
		return
	}
	select {
	case <-p.stop:
		p.dropped.Add(1)
		p.tenantCount(e.OrgID, 1)
		return
	default:
	}
	select {
	case p.queue <- e:
	default:
		p.dropped.Add(1)
		p.tenantCount(e.OrgID, 1)
	}
}
func eventUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: id != uuid.Nil} }
func (p *EventProducer) run() {
	defer close(p.done)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	afterOrg := uuid.Nil
	for {
		var first Event
		select {
		case <-p.stop:
			for {
				select {
				case e := <-p.queue:
					p.dropped.Add(1)
					p.tenantCount(e.OrgID, 1)
				default:
					return
				}
			}
		case first = <-p.queue:
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			afterOrg = p.sweep(ctx, afterOrg)
			cancel()
			continue
		}
		batch := []Event{first}
		for len(batch) < 64 {
			select {
			case e := <-p.queue:
				batch = append(batch, e)
			default:
				goto write
			}
		}
	write:
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := p.writeBatch(ctx, batch)
		cancel()
		for _, e := range batch {
			if err != nil {
				p.storageFailures.Add(1)
				p.tenantCount(e.OrgID, 2)
			} else {
				p.emitted.Add(1)
				p.tenantCount(e.OrgID, 0)
			}
		}
	}
}

// A bounded cursor sweep visits quiet tenants after restart as well as tenants
// emitting new events. Row/age cleanup is asynchronous; errors are observable.
func (p *EventProducer) sweep(ctx context.Context, after uuid.UUID) uuid.UUID {
	q := sqlc.New(p.pool)
	orgs, err := q.ListAppAccessEventRetentionOrganizations(ctx, sqlc.ListAppAccessEventRetentionOrganizationsParams{AfterOrgID: after, PageLimit: 64})
	if err != nil {
		p.storageFailures.Add(1)
		return after
	}
	if len(orgs) == 0 {
		return uuid.Nil
	}
	for _, org := range orgs {
		if ctx.Err() != nil {
			return after
		}
		_, err = q.PruneAppAccessEvents(ctx, sqlc.PruneAppAccessEventsParams{OrgID: org, BeforeTime: time.Now().Add(-30 * 24 * time.Hour), RetainedRows: 10000, BatchLimit: 500})
		after = org
		if err != nil {
			p.storageFailures.Add(1)
			p.tenantCount(org, 2)
		}
	}
	return after
}

// Inserts and retention share a transaction: retention failure cannot permit
// repeated telemetry appends to grow persisted history without its row bound.
func (p *EventProducer) writeBatch(ctx context.Context, batch []Event) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := sqlc.New(tx)
	orgs := map[uuid.UUID]struct{}{}
	for _, e := range batch {
		var revision *int64
		if e.Revision > 0 {
			v := e.Revision
			revision = &v
		}
		_, err = q.InsertAppAccessEvent(ctx, sqlc.InsertAppAccessEventParams{OrgID: e.OrgID, AppID: e.AppID, InstallationGeneration: e.InstallationGeneration, Revision: revision, ServingGeneration: eventUUID(e.ServingGeneration), UserID: eventUUID(e.UserID), GatewayID: eventUUID(e.GatewayID), ProxyID: eventUUID(e.ProxyID), SessionID: eventUUID(e.SessionID), StreamID: eventUUID(e.StreamID), EventKind: e.Kind, Outcome: e.Outcome, Reason: e.Reason})
		if err != nil {
			return err
		}
		orgs[e.OrgID] = struct{}{}
	}
	for org := range orgs {
		if _, err = q.PruneAppAccessEvents(ctx, sqlc.PruneAppAccessEventsParams{OrgID: org, BeforeTime: time.Now().Add(-30 * 24 * time.Hour), RetainedRows: 10000, BatchLimit: 500}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Service) WithEventProducer(p *EventProducer) *Service { s.events = p; return s }
func (s *Service) emit(e Event) {
	if s.events != nil {
		s.events.Emit(e)
	}
}

func sessionEvent(r AppSessionRecord, proxy, stream uuid.UUID, kind, outcome, reason string) Event {
	return Event{OrgID: r.Binding.OrgID, AppID: r.Binding.AppID, InstallationGeneration: r.InstallationGeneration, Revision: r.Binding.Revision, ServingGeneration: r.Binding.Generation, UserID: r.UserID, GatewayID: r.Binding.GatewayID, ProxyID: proxy, SessionID: r.ID, StreamID: stream, Kind: kind, Outcome: outcome, Reason: reason}
}

type EventHistory struct {
	Items                             []sqlc.AppAccessEvent
	Emitted, Dropped, StorageFailures uint64
	TelemetryAvailable                bool
}

func (s *Service) ListEvents(ctx context.Context, org uuid.UUID, app, user, sessionID *uuid.UUID, beforeTime *time.Time, beforeID *uuid.UUID, limit int32) (EventHistory, error) {
	out := EventHistory{Items: []sqlc.AppAccessEvent{}}
	if limit < 1 || limit > 100 || (beforeTime == nil) != (beforeID == nil) {
		return out, apierr.BadRequest("invalid_pagination", "invalid event cursor or limit")
	}
	if err := s.requireActiveOrg(ctx, org); err != nil {
		return out, err
	}
	params := sqlc.ListAppAccessEventsParams{OrgID: org, PageLimit: limit}
	if app != nil {
		params.AppID = eventUUID(*app)
	}
	if user != nil {
		params.UserID = eventUUID(*user)
	}
	if sessionID != nil {
		params.SessionID = eventUUID(*sessionID)
	}
	if beforeTime != nil {
		params.BeforeTime = pgtype.Timestamptz{Time: *beforeTime, Valid: true}
		params.BeforeID = eventUUID(*beforeID)
	}
	items, err := sqlc.New(s.pool).ListAppAccessEvents(ctx, params)
	if err != nil {
		return out, appInfrastructureUnavailable()
	}
	out.Items = items
	if s.events != nil {
		counts, available := s.events.TenantCounts(org)
		out.TelemetryAvailable = available
		out.Emitted, out.Dropped, out.StorageFailures = counts[0], counts[1], counts[2]
	}
	return out, nil
}
