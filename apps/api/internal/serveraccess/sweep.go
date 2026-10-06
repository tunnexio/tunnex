package serveraccess

import (
	"context"
	"github.com/google/uuid"
	"log/slog"
	"time"
)

// Run retires unclaimed/expired durable admissions. Active stream watchdogs
// independently enforce their deadlines even when this database work stalls.
func (s *Service) Run(ctx context.Context) {
	if !s.enabled {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var nextRecordingWarning time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
			s.sweepExpired(bounded)
			if err := s.expireRecordings(bounded); err != nil && !time.Now().Before(nextRecordingWarning) {
				slog.Warn("server access recording retention deferred; cleanup will retry")
				nextRecordingWarning = time.Now().Add(time.Minute)
			}
			cancel()
			archiveCtx, archiveCancel := context.WithTimeout(ctx, 2*time.Second)
			if err := s.processRecordingArchives(archiveCtx); err != nil && !time.Now().Before(nextRecordingWarning) {
				slog.Warn("server access recording archive deferred; durable retry pending")
				nextRecordingWarning = time.Now().Add(time.Minute)
			}
			archiveCancel()
		}
	}
}
func (s *Service) sweepExpired(ctx context.Context) error {
	rows, e := s.pool.Query(ctx, `SELECT org_id,id,user_id,CASE WHEN expires_at<=now() THEN 'session_expired' ELSE 'idle_timeout' END FROM server_access_sessions WHERE status IN ('pending','connecting','connected') AND (expires_at<=now() OR idle_deadline<=now() OR status IN ('pending','connecting') AND created_at<now()-interval '30 seconds') ORDER BY created_at LIMIT 128`)
	if e != nil {
		return e
	}
	type item struct {
		org, id, user uuid.UUID
		reason        string
	}
	items := []item{}
	for rows.Next() {
		var i item
		if e = rows.Scan(&i.org, &i.id, &i.user, &i.reason); e != nil {
			rows.Close()
			return e
		}
		items = append(items, i)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, i := range items {
		if e = s.end(ctx, i.org, i.id, i.user, i.reason); e != nil {
			return e
		}
	}
	return nil
}

func (s *Service) Close() {
	s.mu.Lock()
	streams := make([]*liveSession, 0, len(s.live))
	for id, l := range s.live {
		streams = append(streams, l)
		delete(s.live, id)
	}
	s.mu.Unlock()
	for _, l := range streams {
		l.close()
	}
}
