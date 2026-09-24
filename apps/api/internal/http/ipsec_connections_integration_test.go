package http

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// Run only through the guarded isolated database runner. The test owns a unique
// scratch database and closes its pool before dropping that database.
func TestIPsecConnectionsRouterStoreIntegration(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to the isolated fixture database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_ipsec_connections_http_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("scratch database cleanup: %v", err)
		}
	})
	parsed.Path = "/" + name
	if err = db.MigrateTo(parsed.String(), 160); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, actor := uuid.New(), uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'IPsec HTTP settings',$2,'10.198.0.0/24')`, org, "ipsec-http-"+org.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO users(id,email) VALUES($1,$2)`, actor, actor.String()+"@ipsec-http.test"); err != nil {
		t.Fatal(err)
	}
	connection, site, gateway := uuid.New(), uuid.New(), uuid.New()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'test network')`, []any{site, org}},
		{`INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'gateway',$3,$4)`, []any{gateway, org, gateway.String(), site}},
		{`INSERT INTO ipsec_connections(id,org_id,name,site_id,gateway_node_id,historical_site_id,historical_gateway_node_id) VALUES($1,$2,'test connection',$3,$4,$3,$4)`, []any{connection, org, site, gateway}},
	}
	for _, step := range statements {
		if _, err := tx.Exec(ctx, step.query, step.args...); err != nil {
			t.Fatal(err)
		}
	}
	for slot := 1; slot <= 2; slot++ {
		tunnel := uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO ipsec_tunnels(id,org_id,connection_id,slot) VALUES($1,$2,$3,$4)`, tunnel, org, connection, slot); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ipsec_tunnel_secrets(tunnel_id,org_id,connection_id,secret_revision,sealed_psk) VALUES($1,$2,$3,1,'synthetic-SECRET-MARKER')`, tunnel, org, connection); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	role := rbac.RoleOwner
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{IPsecConnections: ipsec.NewConnectionStore(pool), AuthFn: func(*http.Request) *authctx.Principal {
		return &authctx.Principal{UserID: actor, EmailVerified: true, Roles: map[uuid.UUID]string{org: role}}
	}})
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/organizations/" + org.String() + "/ipsec/connections"
	request := func(method, path string, headers []string, want int) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil).WithContext(ctx)
		for _, header := range headers {
			req.Header.Add("If-Match", header)
		}
		router.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s %s status=%d want=%d: %s", method, path, rec.Code, want, rec.Body.String())
		}
		for _, secret := range []string{"synthetic-SECRET-MARKER", "sealed_psk", "secret_revision"} {
			if strings.Contains(rec.Body.String(), secret) {
				t.Fatalf("response leaked %s", secret)
			}
		}
		return rec
	}
	page := request("GET", base+"?limit=1", nil, 200)
	var decoded ipsec.ConnectionPage
	if err := json.Unmarshal(page.Body.Bytes(), &decoded); err != nil || len(decoded.Items) != 1 || decoded.Items[0].ID != connection {
		t.Fatalf("page=%+v err=%v", decoded, err)
	}
	detail := base + "/" + connection.String()
	got := request("GET", detail, nil, 200)
	if got.Header().Get("ETag") != `"1"` {
		t.Fatalf("etag=%s", got.Header().Get("ETag"))
	}
	for _, headers := range [][]string{nil, {`W/"1"`}, {`*`}, {`"1","2"`}, {`"1"`, `"1"`}, {`"9223372036854775808"`}} {
		request("DELETE", detail, headers, 400)
	}
	request("DELETE", detail, []string{`"2"`}, 409)
	role = rbac.RoleMember
	request("GET", detail, nil, 200)
	request("DELETE", detail, []string{`"1"`}, 403)
	role = rbac.RoleOwner
	deleted := request("DELETE", detail, []string{`"1"`}, 200)
	var record ipsec.Connection
	if err := json.Unmarshal(deleted.Body.Bytes(), &record); err != nil || record.DesiredIntent != "deleted" || record.DesiredRevision != 2 || record.SiteID != nil {
		t.Fatalf("deleted=%+v err=%v", record, err)
	}
	if deleted.Header().Get("ETag") != `"2"` {
		t.Fatal("missing successor ETag")
	}
	request("DELETE", detail, []string{`"2"`}, 409)
	request("GET", detail, nil, 200)
	var audits, secrets, tunnels, resources int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM audit_logs WHERE org_id=$1 AND actor_user_id=$2 AND action='ipsec.connection_deleted'),(SELECT count(*) FROM ipsec_tunnel_secrets WHERE connection_id=$3),(SELECT count(*) FROM ipsec_tunnels WHERE connection_id=$3),(SELECT count(*) FROM sites WHERE id=$4)+(SELECT count(*) FROM nodes WHERE id=$5)`, org, actor, connection, site, gateway).Scan(&audits, &secrets, &tunnels, &resources); err != nil {
		t.Fatal(err)
	}
	if audits != 1 || secrets != 0 || tunnels != 0 || resources != 2 {
		t.Fatalf("counts=%d/%d/%d/%d", audits, secrets, tunnels, resources)
	}
}
