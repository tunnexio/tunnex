package connectivity

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/dbconn"
)

type queryTimingKey struct{}
type queryTiming struct {
	start time.Time
	name  string
}
type mailboxTimingTracer struct {
	t       *testing.T
	enabled atomic.Bool
}

var generatedQueryName = regexp.MustCompile(`^-- name: ([A-Za-z0-9_]+) `)

func (tr *mailboxTimingTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !tr.enabled.Load() {
		return ctx
	}
	name := "transaction"
	if match := generatedQueryName.FindStringSubmatch(data.SQL); len(match) == 2 {
		name = match[1]
	}
	return context.WithValue(ctx, queryTimingKey{}, queryTiming{time.Now(), name})
}
func (tr *mailboxTimingTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	q, ok := ctx.Value(queryTimingKey{}).(queryTiming)
	if !ok {
		return
	}
	classification := "ok"
	if data.Err != nil {
		classification = "database_error"
	}
	if errors.Is(data.Err, context.DeadlineExceeded) {
		classification = "deadline"
	}
	if errors.Is(data.Err, context.Canceled) {
		classification = "canceled"
	}
	tr.t.Logf("query=%s ms=%d result=%s", q.name, time.Since(q.start).Milliseconds(), classification)
}

// Isolated database only: exercise the configured relay path (including issuance),
// not the inert legacy profile. Timing logs never include SQL, arguments or errors.
func TestMailboxLatencyPostgres(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated migrated PostgreSQL")
	}
	ctx := context.Background()
	cfg, err := dbconn.ParsePoolConfig(dsn)
	if err != nil {
		t.Fatal("test DB config refused")
	}
	tr := &mailboxTimingTracer{t: t}
	cfg.ConnConfig.Tracer = tr
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("test pool unavailable")
	}
	defer pool.Close()
	org, owner, gateway, device := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal("fixture query failed")
		}
	}
	exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'NAT timing',$2)`, org, "nat-timing-"+org.String())
	defer func() {
		tr.enabled.Store(false)
		if _, err := pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org); err != nil {
			t.Error("fixture organization cleanup failed")
			return
		}
		if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, owner); err != nil {
			t.Error("fixture user cleanup failed")
		}
	}()
	exec(`INSERT INTO users(id,email) VALUES($1,$2)`, owner, owner.String()+"@example.invalid")
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, org, owner)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'timing-gateway',$3)`, gateway, org, gateway.String())
	exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip) VALUES($1,$2,$3,$4,'timing-device',$5,'10.99.0.2')`, device, org, owner, gateway, strings.Repeat("A", 43)+"=")
	sealer, err := crypto.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal("fixture sealer unavailable")
	}
	s := NewStore(pool, sealer)
	if _, err := s.Configure(ctx, org, RelayConfig{Enabled: true, URL: "turns:relay.example.invalid:5349?transport=tcp", Secret: strings.Repeat("s", 32)}); err != nil {
		t.Fatal("fixture profile failed")
	}
	tr.enabled.Store(true)
	p := Principal{DeviceSide, org, owner}
	start := time.Now()
	m, err := s.Create(ctx, p, device)
	t.Logf("operation=create ms=%d deadline=%t", time.Since(start).Milliseconds(), errors.Is(err, context.DeadlineExceeded))
	if err != nil {
		t.Fatal("create failed (see parameter-free timings)")
	}
	b := m.Session.Binding
	start = time.Now()
	if _, err := s.Publish(ctx, p, device, b.SessionID, b.Generation, 1, json.RawMessage(`{"candidate":"timing-fixture"}`)); err != nil {
		t.Fatal("publish failed (see parameter-free timings)")
	}
	t.Logf("operation=publish ms=%d", time.Since(start).Milliseconds())
	start = time.Now()
	if err := s.Close(ctx, p, device, b.SessionID, b.Generation); err != nil {
		t.Fatal("close failed (see parameter-free timings)")
	}
	t.Logf("operation=close ms=%d", time.Since(start).Milliseconds())
}
