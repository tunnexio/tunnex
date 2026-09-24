package ipsec_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/sites"
)

func TestProviderExistingWritersRespectReservations(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	// Close enough to the existing device pool to exercise a legal growth request.
	req.Config.RemotePrefixes = []string{"10.199.1.0/24"}
	store := ipsec.NewConnectionStore(p)
	if _, err := store.CreateProviderDisabled(ctx, org, actor, sealer, req); err != nil {
		t.Fatal(err)
	}
	siteService := sites.NewService(p)
	var pending []uuid.UUID
	for _, cidr := range []string{"10.199.1.0/24", "9.9.9.0/24", "8.8.8.0/24"} {
		sub, err := siteService.AddSubnet(ctx, org, req.SiteID, netip.MustParsePrefix(cidr))
		if err != nil {
			t.Fatalf("pending advertisement refused: %v", err)
		}
		pending = append(pending, sub.ID)
		err = siteService.ApproveSubnet(ctx, actor, org, sub.ID)
		var ae *apierr.Error
		if !errors.As(err, &ae) {
			t.Fatalf("approval missing scoped refusal for %s: %v", cidr, err)
		}
		if !strings.Contains(ae.Message, "ipsec") {
			t.Fatalf("approval not blocked by provider reservation: %v", err)
		}
		var status string
		if err := p.QueryRow(ctx, `SELECT status FROM site_subnets WHERE id=$1`, sub.ID).Scan(&status); err != nil || status != "pending" {
			t.Fatalf("refused approval mutated pending row: %s %v", status, err)
		}
	}
	devService := devices.NewService(p, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := devService.ResizePool(ctx, actor, org, "10.199.0.0/23"); err == nil || !strings.Contains(err.Error(), "ipsec") {
		t.Fatalf("pool growth not refused by provider range: %v", err)
	}
	if _, err := k8s.NewService(p).RegisterCluster(ctx, org, req.SiteID, "provider-conflict", netip.MustParsePrefix("10.199.1.0/24"), netip.MustParsePrefix("10.96.0.0/12"), "clusters.test", uuid.Nil, actor, "", ""); err == nil || !strings.Contains(err.Error(), "ipsec") {
		t.Fatalf("cluster VIP not refused by provider range: %v", err)
	}
	var localID uuid.UUID
	if err := p.QueryRow(ctx, `SELECT id FROM site_subnets WHERE site_id=$1 AND cidr=$2::cidr`, req.SiteID, req.Config.LocalPrefixes[0]).Scan(&localID); err != nil {
		t.Fatal(err)
	}
	if err := siteService.RemoveSubnet(ctx, actor, org, localID); err == nil {
		t.Fatal("provider local subnet removed")
	}
	// Finalization must release provider-only ownership and retain the shared Site.
	if _, err := store.Delete(ctx, org, actor, req.ID, 1); err != nil {
		t.Fatal(err)
	}
	if err := siteService.ApproveSubnet(ctx, actor, org, pending[0]); err != nil {
		t.Fatalf("remote reservation not released: %v", err)
	}
	if err := siteService.ApproveSubnet(ctx, actor, org, pending[1]); err != nil {
		t.Fatalf("underlay reservation not released: %v", err)
	}
	if err := siteService.RemoveSubnet(ctx, actor, org, localID); err != nil {
		t.Fatalf("local reference not released: %v", err)
	}
}

func TestProviderCreateRechecksWinningRangeAndAuthorityChanges(t *testing.T) {
	for _, scenario := range []string{"site approval", "pool growth", "local deletion", "optout", "revocation"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, p, org, actor, sealer, req := providerFixture(t)
			req.Config.RemotePrefixes = []string{"10.199.1.0/24"}
			cfg := p.Config().Copy()
			name := "provider_wait_" + uuid.NewString()
			cfg.ConnConfig.RuntimeParams["application_name"] = name
			servicePool, err := pgxpool.NewWithConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(servicePool.Close)
			tx, err := p.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, org.String()); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "site approval":
				_, err = tx.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.199.1.0/24','approved')`, uuid.New(), req.SiteID)
			case "pool growth":
				_, err = tx.Exec(ctx, `UPDATE organizations SET pool_cidr='10.199.0.0/23' WHERE id=$1`, org)
			case "local deletion":
				_, err = tx.Exec(ctx, `DELETE FROM site_subnets WHERE site_id=$1 AND cidr=$2::cidr`, req.SiteID, req.Config.LocalPrefixes[0])
			case "optout":
				_, err = tx.Exec(ctx, `UPDATE ipsec_org_settings SET enabled=false,revision=revision+1 WHERE org_id=$1`, org)
			case "revocation":
				_, err = tx.Exec(ctx, `UPDATE nodes SET revoked_at=now(),status='revoked' WHERE id=$1`, req.GatewayID)
			}
			if err != nil {
				t.Fatal(err)
			}
			waitctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, e := ipsec.NewConnectionStore(servicePool).CreateProviderDisabled(waitctx, org, actor, sealer, req)
				done <- e
			}()
			deadline := time.Now().Add(5 * time.Second)
			for {
				var blocked bool
				if e := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock')`, name).Scan(&blocked); e != nil {
					t.Fatal(e)
				}
				if blocked {
					break
				}
				select {
				case e := <-done:
					t.Fatalf("create did not wait for competitor: %v", e)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("lock wait not observed")
				}
				time.Sleep(5 * time.Millisecond)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, ipsec.ErrConnectionConflict) && !errors.Is(err, ipsec.ErrConnectionIneligible) {
				t.Fatalf("expected scoped refusal after winner, got %v", err)
			}
			var n int
			if err := p.QueryRow(ctx, `SELECT count(*) FROM ipsec_connections WHERE org_id=$1`, org).Scan(&n); err != nil || n != 0 {
				t.Fatalf("refused create residue=%d %v", n, err)
			}
		})
	}
}

// A provider create holds range ownership while paused at its final audit. The
// opposing real service must wait, then see the committed reservation.
func TestProviderWinningCreateBlocksOpposingWriters(t *testing.T) {
	for _, scenario := range []string{"site approval", "pool growth", "cluster registration", "local removal"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, p, org, actor, sealer, req := providerFixture(t)
			req.Config.RemotePrefixes = []string{"10.199.1.0/24"}
			sub, err := sites.NewService(p).AddSubnet(ctx, org, req.SiteID, netip.MustParsePrefix("10.199.1.0/24"))
			if err != nil {
				t.Fatal(err)
			}
			var local uuid.UUID
			if err := p.QueryRow(ctx, `SELECT id FROM site_subnets WHERE site_id=$1 AND cidr=$2::cidr`, req.SiteID, req.Config.LocalPrefixes[0]).Scan(&local); err != nil {
				t.Fatal(err)
			}
			// This test database is unique and ephemeral; the trigger only delays this audit action.
			if _, err := p.Exec(ctx, `CREATE FUNCTION pause_provider_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='ipsec.connection_created' THEN PERFORM pg_advisory_xact_lock(8821559001); END IF; RETURN NEW; END $$; CREATE TRIGGER pause_provider_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION pause_provider_audit()`); err != nil {
				t.Fatal(err)
			}
			pause, err := p.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer pause.Rollback(ctx)
			if _, err := pause.Exec(ctx, `SELECT pg_advisory_xact_lock(8821559001)`); err != nil {
				t.Fatal(err)
			}
			newPool := func(label string) *pgxpool.Pool {
				c := p.Config().Copy()
				c.ConnConfig.RuntimeParams["application_name"] = label
				v, e := pgxpool.NewWithConfig(ctx, c)
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(v.Close)
				return v
			}
			createName := "provider_creator_" + uuid.NewString()
			writeName := "provider_opponent_" + uuid.NewString()
			creator, writer := newPool(createName), newPool(writeName)
			waitctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			created := make(chan error, 1)
			go func() {
				_, e := ipsec.NewConnectionStore(creator).CreateProviderDisabled(waitctx, org, actor, sealer, req)
				created <- e
			}()
			waitBlocked := func(name string, done <-chan error) {
				deadline := time.Now().Add(5 * time.Second)
				for {
					var b bool
					if e := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock')`, name).Scan(&b); e != nil {
						t.Fatal(e)
					}
					if b {
						return
					}
					select {
					case e := <-done:
						t.Fatalf("operation escaped lock: %v", e)
					default:
					}
					if time.Now().After(deadline) {
						t.Fatal("expected lock wait not seen")
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
			waitBlocked(createName, created)
			written := make(chan error, 1)
			go func() {
				var e error
				switch scenario {
				case "site approval":
					e = sites.NewService(writer).ApproveSubnet(waitctx, actor, org, sub.ID)
				case "pool growth":
					_, e = devices.NewService(writer, nil, slog.New(slog.NewTextHandler(io.Discard, nil))).ResizePool(waitctx, actor, org, "10.199.0.0/23")
				case "cluster registration":
					_, e = k8s.NewService(writer).RegisterCluster(waitctx, org, req.SiteID, "blocked", netip.MustParsePrefix("10.199.1.0/24"), netip.MustParsePrefix("10.96.0.0/12"), "clusters.test", uuid.Nil, actor, "", "")
				case "local removal":
					e = sites.NewService(writer).RemoveSubnet(waitctx, actor, org, local)
				}
				written <- e
			}()
			waitBlocked(writeName, written)
			if err := pause.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-created; err != nil {
				t.Fatalf("winning create failed: %v", err)
			}
			err = <-written
			var ae *apierr.Error
			if !errors.As(err, &ae) {
				t.Fatalf("opposing writer needs scoped refusal: %v", err)
			}
			var status string
			if err := p.QueryRow(ctx, `SELECT status FROM site_subnets WHERE id=$1`, sub.ID).Scan(&status); err != nil || status != "pending" {
				t.Fatalf("loser changed pending advertisement: %s %v", status, err)
			}
		})
	}
}

func TestProviderGuardsPreserveWireGuardNoopsAndCleanup(t *testing.T) {
	ctx, p, org, actor, _, req := providerFixture(t)
	siteService := sites.NewService(p)
	var local uuid.UUID
	if err := p.QueryRow(ctx, `SELECT id FROM site_subnets WHERE site_id=$1 AND cidr=$2::cidr`, req.SiteID, req.Config.LocalPrefixes[0]).Scan(&local); err != nil {
		t.Fatal(err)
	}
	var before, after time.Time
	if err := p.QueryRow(ctx, `SELECT updated_at FROM organizations WHERE id=$1`, org).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := siteService.ApproveSubnet(ctx, actor, org, local); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.NewService(p, nil, slog.New(slog.NewTextHandler(io.Discard, nil))).ResizePool(ctx, actor, org, "10.199.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(ctx, `SELECT updated_at FROM organizations WHERE id=$1`, org).Scan(&after); err != nil || !after.Equal(before) {
		t.Fatalf("WG no-op unexpectedly versions organization: %v", err)
	}
	// A second org has no IPsec settings/history. New guards must not block its
	// pre-existing administrative cleanup paths, including FK cascades.
	other, site := uuid.New(), uuid.New()
	if _, err := p.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'WG only',$2,'10.201.0.0/24')`, other, other.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO sites(id,org_id,name) VALUES($1,$2,'WG only')`, site, other); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.202.0.0/24','approved')`, uuid.New(), site); err != nil {
		t.Fatal(err)
	}
	cluster, err := k8s.NewService(p).RegisterCluster(ctx, other, site, "wg-only", netip.MustParsePrefix("10.203.0.0/24"), netip.MustParsePrefix("10.96.0.0/12"), "clusters.test", uuid.Nil, actor, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `UPDATE organizations SET deleted_at=now() WHERE id=$1`, other); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `DELETE FROM k8s_clusters WHERE id=$1`, cluster.ID); err != nil {
		t.Fatalf("WG soft-deleted org cleanup blocked: %v", err)
	}
	if _, err := p.Exec(ctx, `DELETE FROM sites WHERE id=$1`, site); err != nil {
		t.Fatalf("WG Site cascade after soft-delete blocked: %v", err)
	}
	// Use an audit-free org for physical deletion: the existing append-only
	// audit contract independently forbids deleting an org with audit history.
	fresh, freshSite := uuid.New(), uuid.New()
	if _, err := p.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'WG cascade',$2,'10.210.0.0/24')`, fresh, fresh.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO sites(id,org_id,name) VALUES($1,$2,'WG cascade')`, freshSite, fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.211.0.0/24','approved')`, uuid.New(), freshSite); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, fresh); err != nil {
		t.Fatalf("WG audit-free organization cascade blocked: %v", err)
	}
}
