package db_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
)

type providerOwner struct{ org, site, node, subnet uuid.UUID }

func providerSchemaFixture(t *testing.T) (context.Context, *pgxpool.Pool, string) {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires guarded disposable PostgreSQL fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	name := "tnx_provider_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	if err := db.MigrateTo(u.String(), 159); err != nil {
		t.Fatalf("159 up: %v", err)
	}
	p, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return ctx, p, u.String()
}
func providerSeed(t *testing.T, ctx context.Context, p *pgxpool.Pool) providerOwner {
	t.Helper()
	o := providerOwner{uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	for _, s := range []struct {
		q string
		a []any
	}{
		{`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'provider fixture',$2,'10.200.0.0/24')`, []any{o.org, o.org.String()}},
		{`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'local')`, []any{o.site, o.org}},
		{`INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'gateway',$3,$4)`, []any{o.node, o.org, o.node.String(), o.site}},
		{`INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, []any{o.subnet, o.site}},
	} {
		if _, err := p.Exec(ctx, s.q, s.a...); err != nil {
			t.Fatal(err)
		}
	}
	return o
}
func insertProvider(ctx context.Context, tx pgx.Tx, o providerOwner, id uuid.UUID) error {
	return insertProviderValues(ctx, tx, o, id, "9.9.9.9", "10.20.0.0/16")
}
func insertProviderValues(ctx context.Context, tx pgx.Tx, o providerOwner, id uuid.UUID, customerOutside, remote string) error {
	for _, s := range []struct {
		q string
		a []any
	}{
		{`INSERT INTO ipsec_connections(id,org_id,name,site_id,gateway_node_id,historical_site_id,historical_gateway_node_id,provider_profile) VALUES($1,$2,'provider',$3,$4,$3,$4,'aws-static-ipv4-v1')`, []any{id, o.org, o.site, o.node}},
		{`INSERT INTO ipsec_provider_bindings(connection_id,org_id) VALUES($1,$2)`, []any{id, o.org}},
		{`INSERT INTO ipsec_aws_static_configs(connection_id,org_id,site_id,gateway_node_id,customer_outside_ipv4) VALUES($1,$2,$3,$4,$5)`, []any{id, o.org, o.site, o.node, customerOutside}},
		{`INSERT INTO ipsec_aws_local_prefixes(connection_id,org_id,site_id,subnet_id,cidr) VALUES($1,$2,$3,$4,'10.10.0.0/16')`, []any{id, o.org, o.site, o.subnet}},
		{`INSERT INTO ipsec_aws_remote_prefixes(connection_id,org_id,cidr) VALUES($1,$2,$3)`, []any{id, o.org, remote}},
	} {
		if _, err := tx.Exec(ctx, s.q, s.a...); err != nil {
			return err
		}
	}
	for i := 0; i < 2; i++ {
		tun := uuid.New()
		outside, inside, customer, cloud := "8.8.8.8", "169.254.10.0/30", "169.254.10.1", "169.254.10.2"
		if i == 1 {
			outside, inside, customer, cloud = "1.1.1.1", "169.254.10.4/30", "169.254.10.5", "169.254.10.6"
		}
		for _, s := range []struct {
			q string
			a []any
		}{
			{`INSERT INTO ipsec_tunnels(id,org_id,connection_id,slot) VALUES($1,$2,$3,$4)`, []any{tun, o.org, id, i + 1}},
			{`INSERT INTO ipsec_tunnel_secrets(tunnel_id,org_id,connection_id,secret_revision,sealed_psk) VALUES($1,$2,$3,1,'synthetic-envelope')`, []any{tun, o.org, id}},
			{`INSERT INTO ipsec_aws_tunnel_configs(tunnel_id,org_id,connection_id,slot,gateway_node_id,aws_outside_ipv4,inside_cidr,customer_inside_ipv4,aws_inside_ipv4) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, []any{tun, o.org, id, i + 1, o.node, outside, inside, customer, cloud}},
		} {
			if _, err := tx.Exec(ctx, s.q, s.a...); err != nil {
				return err
			}
		}
	}
	return nil
}
func providerReject(t *testing.T, ctx context.Context, p *pgxpool.Pool, q string, args ...any) {
	t.Helper()
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, q, args...); err == nil {
		err = tx.Commit(ctx)
	}
	if err == nil {
		t.Fatalf("unsafe SQL committed: %s", q)
	}
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || !(strings.HasPrefix(pe.Code, "23") || pe.Code == "P0001") {
		t.Fatalf("expected integrity refusal, got %v", err)
	}
}
func TestIPsecProviderSchemaEmptyRollback(t *testing.T) {
	ctx, p, dsn := providerSchemaFixture(t)
	o := providerSeed(t, ctx, p)
	legacy := uuid.New()
	tunnelIDs := []uuid.UUID{uuid.New(), uuid.New()}
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO ipsec_connections(id,org_id,name,site_id,gateway_node_id,historical_site_id,historical_gateway_node_id) VALUES($1,$2,'existing158',$3,$4,$3,$4)`, legacy, o.org, o.site, o.node); err != nil {
		t.Fatal(err)
	}
	for i, tun := range tunnelIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO ipsec_tunnels(id,org_id,connection_id,slot) VALUES($1,$2,$3,$4)`, tun, o.org, legacy, i+1); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ipsec_tunnel_secrets(tunnel_id,org_id,connection_id,secret_revision,sealed_psk) VALUES($1,$2,$3,1,'preserved-158-envelope')`, tun, o.org, legacy); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	assertLegacy := func() {
		t.Helper()
		var count int
		if err := p.QueryRow(ctx, `SELECT count(*) FROM ipsec_connections c JOIN ipsec_tunnels t ON t.connection_id=c.id JOIN ipsec_tunnel_secrets s ON s.tunnel_id=t.id WHERE c.id=$1 AND c.site_id=$2 AND c.gateway_node_id=$3 AND c.desired_revision=1 AND c.desired_intent='disabled' AND t.id=ANY($4::uuid[]) AND s.sealed_psk='preserved-158-envelope' AND s.secret_revision=1`, legacy, o.site, o.node, tunnelIDs).Scan(&count); err != nil || count != 2 {
			t.Fatalf("legacy158 changed count=%d %v", count, err)
		}
	}
	assertLegacy()
	if err := db.DownOne(dsn); err != nil {
		t.Fatal(err)
	}
	assertLegacy()
	if err := db.MigrateTo(dsn, 159); err != nil {
		t.Fatal(err)
	}
	assertLegacy()
	var n int
	if err := p.QueryRow(ctx, `SELECT count(*) FROM ipsec_provider_bindings`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("n=%d %v", n, err)
	}
}
func TestIPsecProviderSchemaOwnershipAndFinalization(t *testing.T) {
	ctx, p, dsn := providerSchemaFixture(t)
	o := providerSeed(t, ctx, p)
	id := uuid.New()
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = insertProvider(ctx, tx, o, id); err != nil {
		tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE ipsec_provider_bindings SET configuration_sealed=false WHERE connection_id=$1`,
		`INSERT INTO ipsec_aws_remote_prefixes(connection_id,org_id,cidr) SELECT id,org_id,'10.30.0.0/16' FROM ipsec_connections WHERE id=$1`,
		`UPDATE ipsec_provider_bindings SET profile_id='other' WHERE connection_id=$1`,
		`UPDATE ipsec_provider_bindings SET withdrawal_started=true WHERE connection_id=$1`,
		`DELETE FROM ipsec_aws_remote_prefixes WHERE connection_id=$1`,
		`DELETE FROM ipsec_provider_bindings WHERE connection_id=$1`,
		`UPDATE ipsec_aws_remote_prefixes SET cidr='10.30.0.0/16' WHERE connection_id=$1`,
		`WITH d AS (DELETE FROM ipsec_aws_remote_prefixes WHERE connection_id=$1) INSERT INTO ipsec_aws_remote_prefixes(connection_id,org_id,cidr) SELECT id,org_id,'10.30.0.0/16' FROM ipsec_connections WHERE id=$1`,
	} {
		providerReject(t, ctx, p, q, id)
	}
	for _, q := range []string{`DELETE FROM site_subnets WHERE id=$1`, `UPDATE site_subnets SET status='pending' WHERE id=$1`, `UPDATE site_subnets SET cidr='10.11.0.0/16' WHERE id=$1`} {
		providerReject(t, ctx, p, q, o.subnet)
	}
	providerReject(t, ctx, p, `UPDATE organizations SET pool_cidr='10.20.1.0/24' WHERE id=$1`, o.org)
	providerReject(t, ctx, p, `INSERT INTO site_subnets(site_id,cidr,status) VALUES($1,'10.20.1.0/24','approved')`, o.site)
	if _, err = p.Exec(ctx, `INSERT INTO site_subnets(site_id,cidr,status) VALUES($1,'10.20.1.0/24','pending')`, o.site); err != nil {
		t.Fatal(err)
	}
	providerReject(t, ctx, p, `UPDATE site_subnets SET status='approved' WHERE site_id=$1 AND cidr='10.20.1.0/24'`, o.site)
	providerReject(t, ctx, p, `UPDATE organizations SET pool_cidr='9.9.9.0/24' WHERE id=$1`, o.org)
	down, err := db.MigrationsFS.ReadFile("migrations/0159_ipsec_provider.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	providerReject(t, ctx, p, string(down))
	tx, err = p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, table := range []string{"ipsec_aws_local_prefixes", "ipsec_aws_remote_prefixes", "ipsec_aws_tunnel_configs", "ipsec_aws_static_configs"} {
		if _, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE connection_id=$1", id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE ipsec_connections SET desired_intent='deleted',desired_revision=2,site_id=NULL,gateway_node_id=NULL,deleted_at=now(),finalized_at=now() WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"ipsec_tunnel_secrets", "ipsec_tunnels"} {
		if _, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE connection_id=$1", id); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var withdrawn bool
	if err := p.QueryRow(ctx, `SELECT withdrawal_started FROM ipsec_provider_bindings WHERE connection_id=$1`, id).Scan(&withdrawn); err != nil || !withdrawn {
		t.Fatalf("tombstone %t %v", withdrawn, err)
	}
	if _, err := p.Exec(ctx, `DELETE FROM site_subnets WHERE id=$1`, o.subnet); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `UPDATE organizations SET pool_cidr='10.20.1.0/24' WHERE id=$1`, o.org); err != nil {
		t.Fatal(err)
	}
	if err := db.DownOne(dsn); err == nil {
		t.Fatal("tombstone down allowed")
	}
}

func TestIPsecProviderSchemaBoundsAndExistingIdentity(t *testing.T) {
	ctx, p, _ := providerSchemaFixture(t)
	o := providerSeed(t, ctx, p)
	for _, tc := range []struct{ outside, remote string }{{"127.0.0.1", "10.20.0.0/16"}, {"10.1.1.1", "10.20.0.0/16"}, {"9.9.9.9", "100.64.1.0/24"}, {"9.9.9.9", "0.0.0.0/0"}, {"9.9.9.9", "192.0.0.0/8"}} {
		tx, err := p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		err = insertProviderValues(ctx, tx, o, uuid.New(), tc.outside, tc.remote)
		if err == nil {
			err = tx.Commit(ctx)
		} else {
			tx.Rollback(ctx)
		}
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "23514" {
			t.Fatalf("profile bound refusal=%v", err)
		}
	}
	id := uuid.New()
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO ipsec_connections(id,org_id,name,site_id,gateway_node_id,historical_site_id,historical_gateway_node_id) VALUES($1,$2,'legacy identity',$3,$4,$3,$4)`, id, o.org, o.site, o.node); err != nil {
		t.Fatal(err)
	}
	for slot := 1; slot <= 2; slot++ {
		tun := uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO ipsec_tunnels(id,org_id,connection_id,slot) VALUES($1,$2,$3,$4)`, tun, o.org, id, slot); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ipsec_tunnel_secrets(tunnel_id,org_id,connection_id,secret_revision,sealed_psk) VALUES($1,$2,$3,1,'test-envelope')`, tun, o.org, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	providerReject(t, ctx, p, `INSERT INTO ipsec_provider_bindings(connection_id,org_id) VALUES($1,$2)`, id, o.org)
	providerReject(t, ctx, p, `UPDATE ipsec_connections SET provider_profile='aws-static-ipv4-v1',desired_revision=2 WHERE id=$1`, id)
	// A parent claiming a profile cannot commit as identity-only.
	tx, err = p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO ipsec_connections(id,org_id,name,site_id,gateway_node_id,historical_site_id,historical_gateway_node_id,provider_profile) VALUES($1,$2,'incomplete',$3,$4,$3,$4,'aws-static-ipv4-v1')`, uuid.New(), o.org, o.site, o.node); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err == nil {
		t.Fatal("incomplete provider parent committed")
	}
}

func TestIPsecProviderSchemaMirrorsBothDirections(t *testing.T) {
	for _, kind := range []string{"site", "pool", "vip", "underlay", "inside"} {
		t.Run(kind, func(t *testing.T) {
			ctx, p, _ := providerSchemaFixture(t)
			o := providerSeed(t, ctx, p)
			q := `INSERT INTO site_subnets(site_id,cidr,status) VALUES($1,'10.20.1.0/24','approved')`
			args := []any{o.site}
			switch kind {
			case "pool":
				q = `UPDATE organizations SET pool_cidr='10.20.1.0/24' WHERE id=$1`
				args = []any{o.org}
			case "vip":
				q = `INSERT INTO k8s_clusters(org_id,site_id,name,vip_range) VALUES($1,$2,'mirror','10.20.1.0/24')`
				args = []any{o.org, o.site}
			case "underlay":
				q = `INSERT INTO site_subnets(site_id,cidr,status) VALUES($1,'9.9.9.0/24','approved')`
			case "inside":
				q = `INSERT INTO site_subnets(site_id,cidr,status) VALUES($1,'169.254.10.0/24','approved')`
			}
			// Baseline range first: provider creation must refuse, with no partial state.
			tx, err := p.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, q, args...); err != nil {
				t.Fatal(err)
			}
			if err := insertProvider(ctx, tx, o, uuid.New()); err == nil {
				t.Fatal("provider ignored baseline conflict")
			}
			tx.Rollback(ctx)
			// Provider first: raw baseline mutation must refuse in the opposite direction.
			tx, err = p.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := insertProvider(ctx, tx, o, uuid.New()); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			providerReject(t, ctx, p, q, args...)
		})
	}
}

func TestIPsecProviderSchemaSiteOrgMove(t *testing.T) {
	ctx, p, _ := providerSchemaFixture(t)
	target := providerSeed(t, ctx, p)
	other := providerSeed(t, ctx, p)
	if _, err := p.Exec(ctx, `INSERT INTO site_subnets(site_id,cidr,status) VALUES($1,'10.20.1.0/24','approved')`, other.site); err != nil {
		t.Fatal(err)
	}
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertProvider(ctx, tx, target, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	providerReject(t, ctx, p, `UPDATE sites SET org_id=$1,name='moved' WHERE id=$2`, target.org, other.site)
}

func TestIPsecProviderSchemaOldSnapshots(t *testing.T) {
	for _, kind := range []string{"site", "pool", "vip", "site_move"} {
		for _, providerFirst := range []bool{false, true} {
			t.Run(kind+map[bool]string{true: "_provider_wins", false: "_range_wins"}[providerFirst], func(t *testing.T) {
				ctx, p, _ := providerSchemaFixture(t)
				o := providerSeed(t, ctx, p)
				q := `INSERT INTO site_subnets(site_id,cidr,status) VALUES($1,'10.20.1.0/24','approved')`
				args := []any{o.site}
				switch kind {
				case "pool":
					q = `UPDATE organizations SET pool_cidr='10.20.1.0/24' WHERE id=$1`
					args = []any{o.org}
				case "vip":
					q = `INSERT INTO k8s_clusters(org_id,site_id,name,vip_range) VALUES($1,$2,'old snapshot','10.20.1.0/24')`
					args = []any{o.org, o.site}
				case "site_move":
					other := providerSeed(t, ctx, p)
					if _, err := p.Exec(ctx, `INSERT INTO site_subnets(site_id,cidr,status) VALUES($1,'10.20.1.0/24','approved')`, other.site); err != nil {
						t.Fatal(err)
					}
					q = `UPDATE sites SET org_id=$1,name='moved' WHERE id=$2`
					args = []any{o.org, other.site}
				}
				old, err := p.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
				if err != nil {
					t.Fatal(err)
				}
				defer old.Rollback(ctx)
				var n int
				if err := old.QueryRow(ctx, `SELECT count(*) FROM ipsec_provider_bindings`).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if providerFirst {
					fresh, beginErr := p.Begin(ctx)
					if beginErr != nil {
						t.Fatal(beginErr)
					}
					if err := insertProvider(ctx, fresh, o, uuid.New()); err != nil {
						t.Fatal(err)
					}
					if err := fresh.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					_, err = old.Exec(ctx, q, args...)
				} else {
					if _, err := p.Exec(ctx, q, args...); err != nil {
						t.Fatal(err)
					}
					err = insertProvider(ctx, old, o, uuid.New())
				}
				var pe *pgconn.PgError
				if !errors.As(err, &pe) || pe.Code != "40001" {
					t.Fatalf("older snapshot must serialize-refuse: %v", err)
				}
			})
		}
	}
}
