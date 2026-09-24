package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAgentIPsecMaterialAuthorityRaces(t *testing.T) {
	for _, kind := range []string{"disable", "revoke"} {
		t.Run(kind, func(t *testing.T) {
			dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
			if dsn == "" {
				t.Skip("requires guarded isolated PostgreSQL")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			t.Cleanup(cancel)
			admin, err := pgxpool.New(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(admin.Close)
			u, err := url.Parse(dsn)
			if err != nil {
				t.Fatal(err)
			}
			name := "tnx_runtime_http_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				c, stop := context.WithTimeout(context.Background(), 10*time.Second)
				defer stop()
				if _, err := admin.Exec(c, "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
					t.Error(err)
				}
			})
			u.Path = "/" + name
			if err := db.MigrateTo(u.String(), 160); err != nil {
				t.Fatal(err)
			}
			pool, err := pgxpool.New(ctx, u.String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			org, actor, site, gateway, id := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
			for _, s := range []struct {
				q string
				a []any
			}{
				{`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'provider HTTP',$2,'10.198.0.0/24')`, []any{org, org.String()}},
				{`INSERT INTO users(id,email) VALUES($1,$2)`, []any{actor, actor.String() + "@provider-http.test"}},
				{`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'local')`, []any{site, org}},
				{`INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, []any{uuid.New(), site}},
				{`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,capabilities,policy_reported_at) VALUES($1,$2,'gateway',$3,$4,'{"ipsec_config_version":1}',clock_timestamp())`, []any{gateway, org, "010203", site}},
			} {
				if _, err := pool.Exec(ctx, s.q, s.a...); err != nil {
					t.Fatal(err)
				}
			}

			sealer, err := crypto.NewSealer(bytes.Repeat([]byte{0x67}, 32))
			if err != nil {
				t.Fatal(err)
			}
			store := ipsec.NewConnectionStore(pool)
			store.ConfigureRuntimePolicy(policy.CompileIPsecRuntimePolicy)
			if _, err = ipsec.NewSettingsStore(pool).Configure(ctx, org, actor, true, 0); err != nil {
				t.Fatal(err)
			}
			var input api.IPsecConfigurationCheckInput
			if err = json.Unmarshal([]byte(configurationCheckFixture), &input); err != nil {
				t.Fatal(err)
			}
			cfg, err := privateIPsecConfiguration(input)
			if err != nil {
				t.Fatal(err)
			}
			c, err := store.CreateProviderDisabled(ctx, org, actor, sealer, ipsec.CreateProviderRequest{ID: id, SiteID: site, GatewayID: gateway, Name: "runtime HTTP", TunnelIDs: [2]uuid.UUID{uuid.New(), uuid.New()}, Config: cfg})
			if err != nil {
				t.Fatal(err)
			}
			c, err = store.SetIntent(ctx, org, actor, id, c.DesiredRevision, "enabled")
			if err != nil {
				t.Fatal(err)
			}

			principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: gateway, CertificateSerial: "010203"}
			entered, release := make(chan struct{}), make(chan struct{})
			store.ConfigureRuntimePolicy(func(ctx context.Context, q *sqlc.Queries, in ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
				p, e := policy.CompileIPsecRuntimePolicy(ctx, q, in)
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return ipsec.RuntimePolicy{}, ctx.Err()
				}
				return p, e
			})
			materialDone := make(chan error, 1)
			go func() { _, e := store.Material(ctx, principal, id, c.DesiredRevision, sealer); materialDone <- e }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			config, e := pgxpool.ParseConfig(u.String())
			if e != nil {
				close(release)
				t.Fatal(e)
			}
			appname := "ipsec_race_" + uuid.NewString()
			config.ConnConfig.RuntimeParams["application_name"] = appname
			writerPool, e := pgxpool.NewWithConfig(ctx, config)
			if e != nil {
				close(release)
				t.Fatal(e)
			}
			defer writerPool.Close()
			writerDone := make(chan error, 1)
			go func() {
				var e error
				if kind == "disable" {
					_, e = ipsec.NewConnectionStore(writerPool).SetIntent(ctx, org, actor, id, c.DesiredRevision, "disabled")
				} else {
					_, e = writerPool.Exec(ctx, `UPDATE nodes SET revoked_at=clock_timestamp() WHERE id=$1`, gateway)
				}
				writerDone <- e
			}()
			blocked := false
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if e = pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND cardinality(pg_blocking_pids(pid))>0)`, appname).Scan(&blocked); e != nil {
					break
				}
				if blocked {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			close(release)
			if e = <-materialDone; e != nil {
				t.Fatal(e)
			}
			if e = <-writerDone; e != nil {
				t.Fatal(e)
			}
			if !blocked {
				t.Fatal("authority writer failed to serialize")
			}
			store.ConfigureRuntimePolicy(policy.CompileIPsecRuntimePolicy)
			_, e = store.Material(ctx, principal, id, c.DesiredRevision, sealer)
			want := ipsec.ErrConnectionConflict
			if kind == "revoke" {
				want = ipsec.ErrRuntimeUnauthorized
			}
			if !errors.Is(e, want) {
				t.Fatalf("stale authority material returned %v", e)
			}
			var delivered int64
			if e = pool.QueryRow(ctx, `SELECT last_potentially_delivered_revision FROM ipsec_runtime_state WHERE connection_id=$1`, id).Scan(&delivered); e != nil || delivered != c.DesiredRevision {
				t.Fatal("committed obligation lost", e)
			}
			if kind == "revoke" {
				if _, e = store.SetIntent(ctx, org, actor, id, c.DesiredRevision, "disabled"); e != nil {
					t.Fatal(e)
				}
			}
			current, e := store.Read(ctx, org, id)
			if e != nil || current.CleanupState != "pending" {
				t.Fatal("withdrawal lost cleanup obligation", e)
			}
		})
	}
}
