package serveraccess

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// SA-UI-1. The installation capability is a server-administrator setting. The host environment
// (TUNNEX_SERVER_ACCESS_ENABLED) only seeds it until the first save; TUNNEX_SERVER_ACCESS_LOCKED is an
// operator hard-off that no saved value can override. Reads are fail-closed: an unreadable setting is
// off, never "fall back to the environment".

// installationCacheTTL bounds how long a replica may act on a stale value. Every live terminal renews
// its authority each second through available(), so disabling reaches every replica within ~1-2s.
const installationCacheTTL = time.Second

// ReasonInstallationDisabled is the session end reason written when an administrator turns the
// installation capability off.
const ReasonInstallationDisabled = "server_access_disabled"

type InstallationView struct {
	// Enabled is the administrator's desired value (saved, or the environment seed before any save).
	Enabled bool
	// Effective is what the installation actually enforces: Enabled AND NOT Locked.
	Effective bool
	Locked    bool
	// Source is "environment" until the first save, then "database".
	Source    string
	Version   int64
	UpdatedAt *time.Time
}

type InstallationUpdate struct {
	Enabled         bool
	ExpectedVersion int64
}

type installationCache struct {
	mu        sync.Mutex
	effective bool
	readAt    time.Time
}

// WithInstallationLock applies TUNNEX_SERVER_ACCESS_LOCKED.
func (s *Service) WithInstallationLock(locked bool) *Service {
	s.locked = locked
	return s
}

func (s *Service) readInstallation(ctx context.Context, q sqlc.DBTX) (InstallationView, error) {
	v := InstallationView{Enabled: s.seed, Locked: s.locked, Source: "environment"}
	if q == nil {
		v.Effective = v.Enabled && !v.Locked
		return v, nil
	}
	row, e := sqlc.New(q).GetServerAccessInstallationSettings(ctx)
	if errors.Is(e, pgx.ErrNoRows) {
		v.Effective = v.Enabled && !v.Locked
		return v, nil
	}
	if e != nil {
		return InstallationView{Locked: s.locked}, e
	}
	at := row.UpdatedAt
	v.Enabled, v.Version, v.Source, v.UpdatedAt = row.Enabled, row.Version, "database", &at
	v.Effective = v.Enabled && !v.Locked
	return v, nil
}

// Installation returns the saved/seeded installation setting for server administrators.
func (s *Service) Installation(ctx context.Context) (InstallationView, error) {
	if s.pool == nil {
		return s.readInstallation(ctx, nil)
	}
	return s.readInstallation(ctx, s.pool)
}

// InstallationEffective is the fail-closed, briefly cached capability every gate uses.
func (s *Service) InstallationEffective(ctx context.Context) bool {
	if s.locked {
		return false
	}
	if s.pool == nil {
		return s.seed
	}
	s.install.mu.Lock()
	defer s.install.mu.Unlock()
	if !s.install.readAt.IsZero() && time.Since(s.install.readAt) < installationCacheTTL {
		return s.install.effective
	}
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	v, e := s.readInstallation(bounded, s.pool)
	s.install.effective = e == nil && v.Effective
	s.install.readAt = time.Now()
	return s.install.effective
}

func (s *Service) setInstallationCache(effective bool) {
	s.install.mu.Lock()
	s.install.effective, s.install.readAt = effective, time.Now()
	s.install.mu.Unlock()
}

func installationInvalid() error {
	return apierr.BadRequest("server_access_installation_invalid", "Reload the Server Access setting before saving.")
}

// SaveInstallation records the administrator's choice. Enabling is refused while the environment lock
// is set. Disabling ends every active terminal session durably (each individually audited) before the
// call returns; other replicas observe the ended rows on their next one-second renewal.
func (s *Service) SaveInstallation(ctx context.Context, actor uuid.UUID, in InstallationUpdate) (InstallationView, int, error) {
	if actor == uuid.Nil || in.ExpectedVersion < 0 {
		return InstallationView{}, 0, installationInvalid()
	}
	if in.Enabled && s.locked {
		return InstallationView{}, 0, apierr.Conflict("server_access_locked", "Server Access is locked off by the server environment (TUNNEX_SERVER_ACCESS_LOCKED). Remove the lock on the host to enable it.")
	}
	if s.pool == nil {
		return InstallationView{}, 0, apierr.New(503, "server_access_installation_unavailable", "The Server Access setting is unavailable.")
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return InstallationView{}, 0, e
	}
	defer tx.Rollback(ctx)
	q := sqlc.New(tx)
	if e = q.LockServerAccessInstallationSettings(ctx); e != nil {
		return InstallationView{}, 0, e
	}
	before, e := s.readInstallation(ctx, tx)
	if e != nil {
		return InstallationView{}, 0, e
	}
	if before.Version != in.ExpectedVersion {
		return InstallationView{}, 0, apierr.Conflict("server_access_installation_changed", "The Server Access setting changed. Reload it before saving.")
	}
	row, e := q.UpsertServerAccessInstallationSettings(ctx, sqlc.UpsertServerAccessInstallationSettingsParams{Enabled: in.Enabled, Version: before.Version + 1, UpdatedBy: pgtype.UUID{Bytes: actor, Valid: true}})
	if e != nil {
		return InstallationView{}, 0, e
	}
	after := InstallationView{Enabled: row.Enabled, Locked: s.locked, Effective: row.Enabled && !s.locked, Source: "database", Version: row.Version, UpdatedAt: &row.UpdatedAt}
	var active int
	if !after.Effective {
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM server_access_sessions WHERE status IN ('pending','connecting','connected')`).Scan(&active); e != nil {
			return InstallationView{}, 0, e
		}
	}
	targetType, targetID := "server_access_installation_settings", "deployment"
	meta, _ := json.Marshal(map[string]any{"enabled": after.Enabled, "previous_enabled": before.Enabled, "previous_source": before.Source, "effective": after.Effective, "locked": s.locked, "version": after.Version, "active_sessions": active})
	if _, e = q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{ActorUserID: pgtype.UUID{Bytes: actor, Valid: true}, Action: "server_access.installation_updated", TargetType: &targetType, TargetID: &targetID, Metadata: meta}); e != nil {
		return InstallationView{}, 0, e
	}
	if e = tx.Commit(ctx); e != nil {
		return InstallationView{}, 0, e
	}
	s.setInstallationCache(after.Effective)
	ended := 0
	if !after.Effective {
		ended, e = s.endAllActive(ctx, actor, ReasonInstallationDisabled)
		if e != nil {
			// The setting is saved and every gate already refuses; renewals end the rest within seconds.
			return after, ended, apierr.New(503, "server_access_sessions_pending_close", "Server Access is off. Some active sessions could not be ended yet; they will close on their next authority check.")
		}
	}
	return after, ended, nil
}

// endAllActive ends every active terminal session across all organizations and closes local streams.
func (s *Service) endAllActive(ctx context.Context, actor uuid.UUID, reason string) (int, error) {
	ended := 0
	for {
		rows, e := s.pool.Query(ctx, `SELECT org_id,id FROM server_access_sessions WHERE status IN ('pending','connecting','connected') ORDER BY created_at LIMIT 256`)
		if e != nil {
			return ended, e
		}
		type item struct{ org, id uuid.UUID }
		var batch []item
		for rows.Next() {
			var i item
			if e = rows.Scan(&i.org, &i.id); e != nil {
				rows.Close()
				return ended, e
			}
			batch = append(batch, i)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return ended, e
		}
		if len(batch) == 0 {
			break
		}
		for _, i := range batch {
			if e = s.end(ctx, i.org, i.id, actor, reason); e != nil {
				return ended, e
			}
			ended++
		}
	}
	// Streams this replica holds for sessions that were already ended elsewhere close here too.
	s.Close()
	return ended, nil
}
