package ipsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

// Direct seeding proves storage reads/finalization, not creation eligibility.
func seedStoredConnection(t *testing.T, ctx context.Context, p *pgxpool.Pool, org uuid.UUID) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	id, site, node := uuid.New(), uuid.New(), uuid.New()
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	steps := []struct {
		q string
		a []any
	}{
		{`INSERT INTO sites(id,org_id,name) VALUES($1,$2,$3)`, []any{site, org, "shared-site-" + site.String()}},
		{`INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,$5,$3,$4)`, []any{node, org, node.String(), site, "gateway-" + node.String()}},
		{`INSERT INTO ipsec_connections(id,org_id,name,site_id,gateway_node_id,historical_site_id,historical_gateway_node_id) VALUES($1,$2,'connection',$3,$4,$3,$4)`, []any{id, org, site, node}},
	}
	for _, s := range steps {
		if _, err := tx.Exec(ctx, s.q, s.a...); err != nil {
			t.Fatal(err)
		}
	}
	for slot := 1; slot <= 2; slot++ {
		tun := uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO ipsec_tunnels(id,org_id,connection_id,slot) VALUES($1,$2,$3,$4)`, tun, org, id, slot); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ipsec_tunnel_secrets(tunnel_id,org_id,connection_id,secret_revision,sealed_psk) VALUES($1,$2,$3,1,'synthetic-secret-MUST-NOT-APPEAR')`, tun, org, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return id, site, node
}
func TestConnectionsScopedRedaction(t *testing.T) {
	ctx, p, org, _ := settingsFixture(t)
	s := ipsec.NewConnectionStore(p)
	items, err := s.List(ctx, org)
	if err != nil || items == nil || len(items) != 0 {
		t.Fatalf("empty=%v err=%v", items, err)
	}
	id, site, node := seedStoredConnection(t, ctx, p, org)
	got, err := s.Read(ctx, org, id)
	if err != nil || got.ID != id || got.SiteID == nil || *got.SiteID != site || got.GatewayNodeID == nil || *got.GatewayNodeID != node || got.DesiredRevision != 1 || got.DesiredIntent != "disabled" {
		t.Fatalf("read=%+v err=%v", got, err)
	}
	items, err = s.List(ctx, org)
	if err != nil || len(items) != 1 || items[0].ID != id {
		t.Fatalf("list=%v err=%v", items, err)
	}
	raw, _ := json.Marshal(items)
	for _, bad := range []string{"synthetic-secret", "sealed_psk", "secret_revision", "tunnel"} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("leaked %s", bad)
		}
	}
	other := uuid.New()
	if _, err := p.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'other',$2,'10.198.0.0/24')`, other, other.String()); err != nil {
		t.Fatal(err)
	}
	if list, err := s.List(ctx, other); err != nil || len(list) != 0 {
		t.Fatalf("cross org list=%v %v", list, err)
	}
	if _, err := s.Delete(ctx, other, uuid.New(), id, 1); !errors.Is(err, ipsec.ErrConnectionNotFound) {
		t.Fatalf("cross org delete=%v", err)
	}
	if _, err := s.Read(ctx, other, id); !errors.Is(err, ipsec.ErrConnectionNotFound) {
		t.Fatalf("cross-org=%v", err)
	}
	if _, err := s.Read(ctx, org, uuid.New()); !errors.Is(err, ipsec.ErrConnectionNotFound) {
		t.Fatalf("missing=%v", err)
	}
	var n int
	if err := p.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1`, org).Scan(&n); err != nil || n != 0 {
		t.Fatalf("read audit=%d %v", n, err)
	}
}
func TestConnectionsDeleteCASAndPreservation(t *testing.T) {
	ctx, p, org, actor := settingsFixture(t)
	id, site, node := seedStoredConnection(t, ctx, p, org)
	s := ipsec.NewConnectionStore(p)
	if _, err := s.Delete(ctx, org, uuid.Nil, id, 1); !errors.Is(err, ipsec.ErrConnectionInvalid) {
		t.Fatalf("nil actor=%v", err)
	}
	for _, rev := range []int64{0, -1, math.MaxInt64} {
		if _, err := s.Delete(ctx, org, actor, id, rev); !errors.Is(err, ipsec.ErrConnectionInvalid) {
			t.Fatalf("invalid revision=%v", err)
		}
	}
	if _, err := s.Delete(ctx, org, actor, id, 2); !errors.Is(err, ipsec.ErrConnectionConflict) {
		t.Fatalf("future=%v", err)
	}
	if _, err := s.Delete(ctx, uuid.New(), actor, id, 1); !errors.Is(err, ipsec.ErrConnectionNotFound) {
		t.Fatalf("scope=%v", err)
	}
	if _, err := p.Exec(ctx, `UPDATE nodes SET revoked_at=now() WHERE id=$1`, node); err != nil {
		t.Fatal(err)
	}
	got, err := s.Delete(ctx, org, actor, id, 1)
	if err != nil || got.DesiredIntent != "deleted" || got.DesiredRevision != 2 || got.SiteID != nil || got.GatewayNodeID != nil || got.DeletedAt == nil || got.FinalizedAt == nil || got.HistoricalSiteID != site || got.HistoricalGatewayNodeID != node {
		t.Fatalf("delete=%+v err=%v", got, err)
	}
	for _, rev := range []int64{1, 2} {
		if _, err := s.Delete(ctx, org, actor, id, rev); !errors.Is(err, ipsec.ErrConnectionConflict) {
			t.Fatalf("repeat=%v", err)
		}
	}
	var tunnels, secrets, sites, nodes, audits int
	err = p.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_tunnels WHERE connection_id=$1),(SELECT count(*) FROM ipsec_tunnel_secrets WHERE connection_id=$1),(SELECT count(*) FROM sites WHERE id=$2),(SELECT count(*) FROM nodes WHERE id=$3),(SELECT count(*) FROM audit_logs WHERE org_id=$4 AND actor_user_id=$5 AND action='ipsec.connection_deleted' AND target_id=$6 AND metadata->>'revision'='2')`, id, site, node, org, actor, id.String()).Scan(&tunnels, &secrets, &sites, &nodes, &audits)
	if err != nil || tunnels != 0 || secrets != 0 || sites != 1 || nodes != 1 || audits != 1 {
		t.Fatalf("counts=%d/%d/%d/%d/%d %v", tunnels, secrets, sites, nodes, audits, err)
	}
	var metadata string
	if err := p.QueryRow(ctx, `SELECT metadata::text FROM audit_logs WHERE org_id=$1 AND action='ipsec.connection_deleted'`, org).Scan(&metadata); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"synthetic-secret", "sealed_psk", "secret_revision"} {
		if strings.Contains(metadata, bad) {
			t.Fatalf("audit exposed %s", bad)
		}
	}
	got, err = s.Read(ctx, org, id)
	if err != nil || got.DesiredIntent != "deleted" {
		t.Fatalf("tombstone=%+v %v", got, err)
	}
	if _, err := p.Exec(ctx, `UPDATE organizations SET deleted_at=now() WHERE id=$1`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(ctx, org, id); !errors.Is(err, ipsec.ErrConnectionNotFound) {
		t.Fatalf("deleted org read=%v", err)
	}
	if _, err := s.List(ctx, org); !errors.Is(err, ipsec.ErrConnectionNotFound) {
		t.Fatalf("deleted org list=%v", err)
	}
}
func TestConnectionsDeleteRollbackAndConcurrency(t *testing.T) {
	ctx, p, org, actor := settingsFixture(t)
	id, site, node := seedStoredConnection(t, ctx, p, org)
	s := ipsec.NewConnectionStore(p)
	if _, err := s.Delete(ctx, org, uuid.New(), id, 1); !errors.Is(err, ipsec.ErrConnectionUnavailable) {
		t.Fatalf("audit failure=%v", err)
	}
	got, err := s.Read(ctx, org, id)
	if err != nil || got.DesiredRevision != 1 || got.DesiredIntent != "disabled" || got.SiteID == nil || *got.SiteID != site || got.GatewayNodeID == nil || *got.GatewayNodeID != node {
		t.Fatalf("rollback=%+v %v", got, err)
	}
	var n int
	if err := p.QueryRow(ctx, `SELECT count(*) FROM ipsec_tunnel_secrets s JOIN ipsec_tunnels t ON t.id=s.tunnel_id WHERE s.connection_id=$1 AND s.sealed_psk='synthetic-secret-MUST-NOT-APPEAR'`, id).Scan(&n); err != nil || n != 2 {
		t.Fatalf("rollback secrets=%d %v", n, err)
	}
	start := make(chan struct{})
	out := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _, err := s.Delete(ctx, org, actor, id, 1); out <- err }()
	}
	close(start)
	wg.Wait()
	close(out)
	success, conflict := 0, 0
	for err := range out {
		if err == nil {
			success++
		} else if errors.Is(err, ipsec.ErrConnectionConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d", success, conflict)
	}
	if err := p.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1`, org).Scan(&n); err != nil || n != 1 {
		t.Fatalf("audits=%d %v", n, err)
	}
}

func TestConnectionsListPage(t *testing.T) {
	ctx, p, org, actor := settingsFixture(t)
	s := ipsec.NewConnectionStore(p)
	empty, err := s.ListPage(ctx, org, nil, 2)
	if err != nil || empty.Items == nil || len(empty.Items) != 0 || empty.NextCursor != nil {
		t.Fatalf("empty=%+v %v", empty, err)
	}
	ids := make([]uuid.UUID, 0, 3)
	for range 3 {
		id, _, _ := seedStoredConnection(t, ctx, p, org)
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	first, err := s.ListPage(ctx, org, nil, 2)
	if err != nil || len(first.Items) != 2 || first.Items[0].ID != ids[0] || first.Items[1].ID != ids[1] || first.NextCursor == nil || *first.NextCursor != ids[1] {
		t.Fatalf("first=%+v %v", first, err)
	}
	second, err := s.ListPage(ctx, org, first.NextCursor, 2)
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != ids[2] || second.NextCursor != nil {
		t.Fatalf("second=%+v %v", second, err)
	}
	exact, err := s.ListPage(ctx, org, &ids[0], 2)
	if err != nil || len(exact.Items) != 2 || exact.NextCursor != nil {
		t.Fatalf("exact full final page=%+v %v", exact, err)
	}
	one, err := s.ListPage(ctx, org, nil, 1)
	if err != nil || len(one.Items) != 1 || one.NextCursor == nil || *one.NextCursor != ids[0] {
		t.Fatalf("one=%+v %v", one, err)
	}
	last, err := s.ListPage(ctx, org, &ids[2], 2)
	if err != nil || last.Items == nil || len(last.Items) != 0 || last.NextCursor != nil {
		t.Fatalf("last=%+v %v", last, err)
	}
	all, err := s.ListPage(ctx, org, nil, 100)
	if err != nil || len(all.Items) != 3 || all.NextCursor != nil {
		t.Fatalf("all=%+v %v", all, err)
	}
	raw, _ := json.Marshal(all)
	for _, bad := range []string{"synthetic-secret", "sealed_psk", "secret_revision", "tunnel"} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("page exposed %s", bad)
		}
	}
	for _, limit := range []int{0, -1, 101, math.MaxInt} {
		if _, err := s.ListPage(ctx, org, nil, limit); !errors.Is(err, ipsec.ErrConnectionInvalid) {
			t.Fatalf("invalid limit %d=%v", limit, err)
		}
	}
	other := uuid.New()
	if _, err := p.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'other',$2,'10.198.0.0/24')`, other, other.String()); err != nil {
		t.Fatal(err)
	}
	foreignID, _, _ := seedStoredConnection(t, ctx, p, other)
	otherPage, err := s.ListPage(ctx, other, nil, 100)
	if err != nil || len(otherPage.Items) != 1 || otherPage.Items[0].ID != foreignID || otherPage.Items[0].OrgID != other || otherPage.NextCursor != nil {
		t.Fatalf("other org page=%+v %v", otherPage, err)
	}
	ownPage, err := s.ListPage(ctx, org, nil, 100)
	if err != nil || len(ownPage.Items) != 3 || ownPage.NextCursor != nil {
		t.Fatalf("own page after foreign seed=%+v %v", ownPage, err)
	}
	for i, item := range ownPage.Items {
		if item.ID != ids[i] || item.OrgID != org {
			t.Fatalf("own page foreign leak=%+v", item)
		}
	}
	page, err := s.ListPage(ctx, org, &foreignID, 100)
	if err != nil {
		t.Fatal(err)
	}
	expected := 0
	for _, id := range ids {
		if id.String() > foreignID.String() {
			expected++
		}
	}
	if len(page.Items) != expected {
		t.Fatalf("foreign cursor items=%d want=%d", len(page.Items), expected)
	}
	for _, item := range page.Items {
		if item.OrgID != org || item.ID == foreignID {
			t.Fatalf("foreign page leak=%+v", item)
		}
	}
	for _, id := range ids {
		if _, err := s.Delete(ctx, org, actor, id, 1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Exec(ctx, `UPDATE organizations SET deleted_at=now() WHERE id=$1`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListPage(ctx, org, nil, 2); !errors.Is(err, ipsec.ErrConnectionNotFound) {
		t.Fatalf("deleted org page=%v", err)
	}
}
