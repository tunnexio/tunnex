package alerts

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

func IPsecKeys() []EventKey {
	return []EventKey{EventIPsecTunnelDown, EventIPsecConnectionDown, EventIPsecStatusUnavailable}
}

type ipsecHealthReader interface {
	List(context.Context, uuid.UUID) ([]ipsec.Connection, error)
	ReadStatus(context.Context, uuid.UUID, uuid.UUID) (ipsec.ConnectionStatus, error)
}

type IPsecProductHealthSource struct {
	q      *sqlc.Queries
	reader ipsecHealthReader
}

func NewIPsecProductHealthSource(pool *pgxpool.Pool, reader ipsecHealthReader) *IPsecProductHealthSource {
	return &IPsecProductHealthSource{q: sqlc.New(pool), reader: reader}
}

func (s *IPsecProductHealthSource) Snapshots(ctx context.Context) ([]ProductHealthSnapshot, error) {
	orgs, err := s.q.ListOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	snapshots := make([]ProductHealthSnapshot, 0, len(orgs))
	for _, org := range orgs {
		connections, err := s.reader.List(ctx, org.ID)
		if err != nil {
			return nil, err
		}
		snapshot := ProductHealthSnapshot{OrgID: org.ID}
		for _, c := range connections {
			if c.DesiredIntent != "enabled" || c.DeletedAt != nil {
				continue
			}
			status, err := s.reader.ReadStatus(ctx, org.ID, c.ID)
			if err != nil {
				return nil, err
			} // Never resolve incidents after a failed read.
			events, retain := ipsecConditions(c, status)
			snapshot.Events = append(snapshot.Events, events...)
			snapshot.RetainDedupKeys = append(snapshot.RetainDedupKeys, retain...)
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

// ReadStatus is the authority for freshness, report ownership and revision checks.
// Unknown evidence retains previous down incidents until a fresh observation.
func ipsecConditions(c ipsec.Connection, status ipsec.ConnectionStatus) ([]Event, []string) {
	prefix := "ipsec:" + c.ID.String()
	event := func(key EventKey, suffix, subject string, severity Severity) Event {
		return Event{OrgID: c.OrgID, Key: key, Severity: severity, DedupKey: prefix + suffix,
			Subject: subject, Resource: &ResourceRef{Type: "ipsec_connection", ID: c.ID.String(), Name: c.Name},
			Fields: map[string]string{"connection_id": c.ID.String(), "connection_name": c.Name}}
	}
	states := [2]string{"unknown", "unknown"}
	if len(status.Tunnels) == 2 && status.Tunnels[0].Slot == 1 && status.Tunnels[1].Slot == 2 {
		states[0], states[1] = status.Tunnels[0].Status, status.Tunnels[1].Status
	}
	var events []Event
	var retain []string
	unknown := false
	for i, state := range states {
		suffix := fmt.Sprintf(":tunnel:%d:down", i+1)
		switch state {
		case "down":
			e := event(EventIPsecTunnelDown, suffix, fmt.Sprintf("IPsec %s tunnel %d is down", c.Name, i+1), SeverityWarning)
			e.Fields["tunnel_slot"] = fmt.Sprint(i + 1)
			events = append(events, e)
		case "up":
		default:
			unknown = true
			retain = append(retain, prefix+suffix)
		}
	}
	if states[0] == "down" && states[1] == "down" {
		events = append(events, event(EventIPsecConnectionDown, ":down", "IPsec "+c.Name+" has both tunnels down", SeverityCritical))
	}
	if unknown {
		events = append(events, event(EventIPsecStatusUnavailable, ":unknown", "IPsec "+c.Name+" tunnel status is unavailable", SeverityWarning))
		// One fresh Up proves the both-down condition has ended; Unknown alone cannot.
		if states[0] != "up" && states[1] != "up" {
			retain = append(retain, prefix+":down")
		}
	}
	return events, retain
}
