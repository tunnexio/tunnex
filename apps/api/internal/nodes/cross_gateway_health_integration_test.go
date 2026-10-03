package nodes

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestCrossGatewayDatabaseHealthMatchesServedArtifact(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, a, b := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug,cross_gateway_clients_enabled) VALUES($1,'health',$2,true)`, org, org.String()); err != nil {
		t.Fatal(err)
	}
	for i, id := range []uuid.UUID{a, b} {
		key := make([]byte, 32)
		key[0] = byte(i + 1)
		if _, err := pool.Exec(ctx, `INSERT INTO nodes(id,org_id,name,cert_serial,wg_public_key,endpoint,enrolled_kind) VALUES($1,$2,$3,$3,$4,'gateway.example:51820','gateway')`, id, org, id.String(), base64.StdEncoding.EncodeToString(key)); err != nil {
			t.Fatal(err)
		}
	}
	q := sqlc.New(pool)
	s := &Service{pool: pool, q: q}
	node := sqlc.Node{ID: a, OrgID: org, PolicyReportedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}}
	topo, err := s.loadSiteTopology(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	artifact := func() *policyspec.Compiled {
		return &policyspec.Compiled{Version: 1, NodeID: a.String(), Mode: "enforcing"}
	}
	served := s.finalizeArtifact(topo, node, artifact())
	if !served.CrossGatewayClients || served.Version != 10 {
		t.Fatal("fixture must carry cross-gateway transport on a siteless gateway")
	}
	applied := policyspec.CanonicalHash(*served)
	node.Capabilities = capsJSON(map[string]any{"policy_hash": applied, "max_policy_version": 10})
	s.policy = stubHashProvider{pol: artifact()}
	health := s.PolicyHealthForNodes(ctx, org, []sqlc.Node{node})[a]
	if !health.PushKnown || health.PushedHash != applied || health.Degraded {
		t.Errorf("healthy served artifact mismatches health baseline: %+v", health)
	}
	s.policy = stubHashProvider{pol: artifact()}
	s.trackDesync(ctx, node, applied)
	if desyncSince(t, pool, a).Valid {
		t.Error("matching cross-gateway artifact falsely stamped desync")
	}
	s.policy = stubHashProvider{pol: artifact()}
	s.trackDesync(ctx, node, "old-artifact")
	if !desyncSince(t, pool, a).Valid {
		t.Fatal("real cross-gateway mismatch must still stamp desync")
	}
	s.policy = stubHashProvider{pol: artifact()}
	s.trackDesync(ctx, node, applied)
	if desyncSince(t, pool, a).Valid {
		t.Fatal("reconvergence must clear desync")
	}
}
