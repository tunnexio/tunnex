package connectivity

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

type GatewayPage struct {
	Items []Mailbox
	Next  uuid.UUID
}

// Pending reauthorizes each candidate instead of returning an unguarded join.
// Next is the last examined ID, even when every item in the page was denied.
func (s *Store) Pending(ctx context.Context, p Principal, after uuid.UUID) (GatewayPage, error) {
	if s == nil || s.pool == nil || p.Side != GatewaySide || p.OrgID == uuid.Nil || p.SubjectID == uuid.Nil {
		return GatewayPage{}, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	keys, err := sqlc.New(s.pool).ListGatewayConnectivityKeys(ctx, sqlc.ListGatewayConnectivityKeysParams{OrgID: p.OrgID, GatewayID: p.SubjectID, AfterDeviceID: after})
	if err != nil {
		return GatewayPage{}, err
	}
	out := GatewayPage{Items: make([]Mailbox, 0, len(keys))}
	for _, key := range keys {
		m, err := s.Read(ctx, p, key.DeviceID, key.SessionID, uint64(key.Generation))
		if errors.Is(err, ErrDenied) {
			continue
		}
		if err != nil {
			return GatewayPage{}, err
		}
		out.Items = append(out.Items, m)
	}
	if len(keys) == 64 {
		out.Next = keys[len(keys)-1].DeviceID
	}
	return out, nil
}
