package metrics

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// RegisterPool reports process-local pool counters without acquiring a database
// connection. No SQL, DSN, tenant or identity labels are exposed.
func RegisterPool(reg *prometheus.Registry, pool *pgxpool.Pool) {
	for _, gauge := range []struct {
		name, help string
		value      func(*pgxpool.Stat) float64
	}{
		{"tunnex_db_pool_max_connections", "Configured maximum connections, including scheduler leadership.", func(s *pgxpool.Stat) float64 { return float64(s.MaxConns()) }},
		{"tunnex_db_pool_acquired_connections", "Currently acquired database connections.", func(s *pgxpool.Stat) float64 { return float64(s.AcquiredConns()) }},
		{"tunnex_db_pool_idle_connections", "Currently idle database connections.", func(s *pgxpool.Stat) float64 { return float64(s.IdleConns()) }},
	} {
		reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: gauge.name, Help: gauge.help}, func() float64 { return gauge.value(pool.Stat()) }))
	}
	for _, counter := range []struct {
		name, help string
		value      func(*pgxpool.Stat) float64
	}{
		{"tunnex_db_pool_acquires_total", "Successful database connection acquisitions.", func(s *pgxpool.Stat) float64 { return float64(s.AcquireCount()) }},
		{"tunnex_db_pool_acquire_seconds_total", "Cumulative duration of successful connection acquisitions.", func(s *pgxpool.Stat) float64 { return s.AcquireDuration().Seconds() }},
		{"tunnex_db_pool_empty_acquires_total", "Successful acquisitions that waited for an available connection.", func(s *pgxpool.Stat) float64 { return float64(s.EmptyAcquireCount()) }},
		{"tunnex_db_pool_empty_wait_seconds_total", "Cumulative empty-pool wait time for successful acquisitions.", func(s *pgxpool.Stat) float64 { return s.EmptyAcquireWaitTime().Seconds() }},
		{"tunnex_db_pool_canceled_acquires_total", "Connection acquisitions canceled while waiting.", func(s *pgxpool.Stat) float64 { return float64(s.CanceledAcquireCount()) }},
	} {
		reg.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{Name: counter.name, Help: counter.help}, func() float64 { return counter.value(pool.Stat()) }))
	}
}
