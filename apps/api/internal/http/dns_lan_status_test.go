package http

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"testing"
	"time"
)

func TestNodeAPIExposesLANBindEvidenceWithReceiptTime(t *testing.T) {
	id := uuid.New()
	reported := time.Now().UTC()
	caps, _ := json.Marshal(nodes.NodeCapabilities{DNSLANListeners: []nodes.DNSLANListenerState{{Address: "192.168.1.39", Interface: "eth0", Ready: false, Error: "TCP port53 occupied", ProfileIDs: []string{id.String()}}}})
	n := toAPINode(sqlc.Node{Capabilities: caps, PolicyReportedAt: pgtype.Timestamptz{Time: reported, Valid: true}})
	if n.DnsLanListeners == nil || len(*n.DnsLanListeners) != 1 || (*n.DnsLanListeners)[0].Ready || (*n.DnsLanListeners)[0].ProfileIds[0] != id || n.DnsLanReportedAt == nil || !n.DnsLanReportedAt.Equal(reported) {
		t.Fatal("listener evidence lost or falsely ready", n)
	}
	old := toAPINode(sqlc.Node{})
	if old.DnsLanListeners != nil || old.DnsLanReportedAt != nil {
		t.Fatal("legacy node manufactured DNS readiness")
	}
}
