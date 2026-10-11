package devices

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"strings"
	"testing"
	"time"
)

func TestSelectedGatewayAppliedMTUReachesNormalExport(t *testing.T) {
	n := sqlc.Node{Endpoint: "192.0.2.1:51820", WgPublicKey: "public", Capabilities: []byte(`{"wireguard_applied_mtu":1380}`), PolicyReportedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}}
	s := &Service{}
	mtu := s.selectedGatewayMTU(context.Background(), uuid.New(), n, n.Endpoint, n.WgPublicKey)
	config := buildConfig(configParams{mtu: mtu, address: "10.99.0.2", privateKey: "synthetic", serverPubKey: "synthetic", endpoint: n.Endpoint})
	if !strings.Contains(config, "MTU = 1380\n") {
		t.Fatal("normal export did not consume actual applied gateway MTU")
	}
	if got := buildConfig(configParams{mtu: sandboxMTU}); !strings.Contains(got, "MTU = 1280\n") {
		t.Fatal("sandbox MTU changed")
	}
	n.PolicyReportedAt.Valid = false
	if got := s.selectedGatewayMTU(context.Background(), uuid.New(), n, n.Endpoint, n.WgPublicKey); got != 1420 {
		t.Fatal("legacy fallback changed")
	}
}
