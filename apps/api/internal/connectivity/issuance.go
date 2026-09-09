package connectivity

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"strconv"
	"time"
)

var ErrIssuanceLimited = errors.New("connectivity issuance limited")

type IssuanceLimits struct{ Device, Owner, Organization int64 }

func DefaultIssuanceLimits() IssuanceLimits { return IssuanceLimits{6, 30, 300} }

// Startup-only configuration; every CP replica must use the same limits.
// Zero/negative/oversized settings refuse startup, never disable the guard.
func LoadIssuanceLimits(getenv func(string) string) (IssuanceLimits, error) {
	l := DefaultIssuanceLimits()
	for _, setting := range []struct {
		name   string
		target *int64
	}{
		{"TUNNEX_RELAY_ISSUANCE_DEVICE_PER_MINUTE", &l.Device},
		{"TUNNEX_RELAY_ISSUANCE_OWNER_PER_MINUTE", &l.Owner},
		{"TUNNEX_RELAY_ISSUANCE_ORG_PER_MINUTE", &l.Organization},
	} {
		if raw := getenv(setting.name); raw != "" {
			value, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || value < 1 || value > 10000 {
				return l, fmt.Errorf("invalid %s", setting.name)
			}
			*setting.target = value
		}
	}
	return l, nil
}

func (s *Store) WithIssuanceLimits(l IssuanceLimits) *Store {
	copy := *s
	copy.limits = l
	return &copy
}

// The ledger key is NOT a credential: it identifies one session/side/minute
// issuance. Repeated mailbox reads in that minute return the same credentials
// without spending another token or taking the org writer lock.
func (s *Store) reserveIssuance(ctx context.Context, q *sqlc.Queries, b Binding, side Side, now time.Time) (time.Time, error) {
	key := func(at time.Time) uuid.UUID {
		return uuid.NewSHA1(b.SessionID, []byte(fmt.Sprintf("%d:%d", side, at.Unix()/60)))
	}
	exists, err := q.HasConnectivityIssuance(ctx, sqlc.HasConnectivityIssuanceParams{SessionID: key(now), OrgID: b.OrgID})
	if err != nil || exists {
		return now, err
	}
	if err := q.EnsureConnectivityIssuanceLock(ctx, b.OrgID); err != nil {
		return now, err
	}
	if _, err := q.LockConnectivityIssuance(ctx, b.OrgID); err != nil {
		return now, err
	}
	now, err = q.ConnectivityWallClock(ctx)
	if err != nil {
		return now, err
	}
	id := key(now)
	exists, err = q.HasConnectivityIssuance(ctx, sqlc.HasConnectivityIssuanceParams{SessionID: id, OrgID: b.OrgID})
	if err != nil || exists {
		return now, err
	}
	if err := q.PruneConnectivityIssuances(ctx, sqlc.PruneConnectivityIssuancesParams{OrgID: b.OrgID, Cutoff: now.Add(-time.Minute)}); err != nil {
		return now, err
	}
	counts, err := q.CountConnectivityIssuances(ctx, sqlc.CountConnectivityIssuancesParams{OrgID: b.OrgID, OwnerID: b.OwnerID, DeviceID: b.DeviceID})
	if err != nil {
		return now, err
	}
	if counts.DeviceCount >= s.limits.Device || counts.OwnerCount >= s.limits.Owner || counts.OrganizationCount >= s.limits.Organization {
		return now, ErrIssuanceLimited
	}
	err = q.RecordConnectivityIssuance(ctx, sqlc.RecordConnectivityIssuanceParams{SessionID: id, OrgID: b.OrgID, OwnerID: b.OwnerID, DeviceID: b.DeviceID, IssuedAt: now})
	return now, err
}
