package devices

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"strings"
	"testing"
	"time"
)

func TestSelectedGatewayAppliedMTUReachesNormalExport(t *testing.T) {
	s := &Service{}
	for _, tc := range []struct {
		name string
		caps string
		time pgtype.Timestamptz
		want int
	}{
		{"fresh minimum", `{"wireguard_applied_mtu":1280}`, pgtype.Timestamptz{Time: time.Now(), Valid: true}, 1280},
		{"fresh conservative", `{"wireguard_applied_mtu":1380}`, pgtype.Timestamptz{Time: time.Now(), Valid: true}, 1380},
		{"fresh verified maximum", `{"wireguard_applied_mtu":1420}`, pgtype.Timestamptz{Time: time.Now(), Valid: true}, 1420},
		{"missing report", `{"wireguard_applied_mtu":1420}`, pgtype.Timestamptz{}, 1380},
		{"stale report", `{"wireguard_applied_mtu":1420}`, pgtype.Timestamptz{Time: time.Now().Add(-time.Minute * 2), Valid: true}, 1380},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := sqlc.Node{Endpoint: "192.0.2.1:51820", WgPublicKey: "public", Capabilities: []byte(tc.caps), PolicyReportedAt: tc.time}
			mtu := s.selectedGatewayMTU(context.Background(), uuid.New(), n, n.Endpoint, n.WgPublicKey)
			config := buildConfig(configParams{mtu: mtu, address: "10.99.0.2", privateKey: "synthetic", serverPubKey: "synthetic", endpoint: n.Endpoint})
			if !strings.Contains(config, fmt.Sprintf("MTU = %d\n", tc.want)) {
				t.Fatalf("normal export did not consume selected gateway MTU %d", tc.want)
			}
		})
	}
	if got := buildConfig(configParams{mtu: sandboxMTU}); !strings.Contains(got, "MTU = 1280\n") {
		t.Fatal("sandbox MTU changed")
	}
}
