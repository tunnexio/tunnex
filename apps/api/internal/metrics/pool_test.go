package metrics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

func TestPoolMetricsDoNotAcquireOrExposeLabels(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://unused@127.0.0.1:1/unused?sslmode=disable&pool_max_conns=7")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	reg := prometheus.NewRegistry()
	RegisterPool(reg, pool)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(families) != 8 {
		t.Fatalf("unexpected metric count: %d", len(families))
	}
	for _, family := range families {
		if len(family.Metric) != 1 || len(family.Metric[0].Label) != 0 {
			t.Fatal("unexpected cardinality/labels")
		}
		if family.GetName() == "tunnex_db_pool_max_connections" && family.Metric[0].GetGauge().GetValue() != 7 {
			t.Fatal("pool configuration not measured")
		}
	}
	if pool.Stat().AcquireCount() != 0 || pool.Stat().TotalConns() != 0 {
		t.Fatal("scrape contacted database")
	}
}
