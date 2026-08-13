package nodes

import (
	"context"
	"os"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestZZNulProbeSchema(t *testing.T) {
	max := uint64(100)
	s := &openapi3.Schema{Type: &openapi3.Types{"string"}, MaxLength: &max}
	if err := s.VisitJSON("\x00"); err != nil {
		t.Logf("SCHEMA REJECTED: %v", err)
	} else {
		t.Logf("SCHEMA ACCEPTED NUL")
	}
}

func TestZZNulProbeDB(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("no db")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	var out string
	err = pool.QueryRow(ctx, "SELECT $1::text", "\x00").Scan(&out)
	t.Logf("SELECT $1::text with NUL -> err=%v out=%q", err, out)

	// And the actual insert shape, inside a rolled-back tx.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	v := "\x00"
	_, err = tx.Exec(ctx,
		"INSERT INTO node_rekey_challenges (nonce, identifier, identifier_kind, expires_at, cert_serial) VALUES ($1,$2,$3,now()+interval '2 min', CASE WHEN $3 = 'cert_serial' THEN $2 END)",
		[]byte("0123456789012345678901234567890a"), &v, "cert_serial")
	t.Logf("INSERT challenge with NUL identifier -> err=%v", err)

	rows, err := tx.Query(ctx, "UPDATE node_rekey_challenges SET consumed_at = now() WHERE nonce = $1 AND coalesce(identifier, cert_serial) = $2 AND identifier_kind = $3 AND consumed_at IS NULL AND expires_at > now() RETURNING id",
		[]byte("zzzz"), &v, "cert_serial")
	if err != nil {
		t.Logf("CONSUME with NUL -> query err=%v", err)
	} else {
		rows.Close()
		t.Logf("CONSUME with NUL -> rows err=%v", rows.Err())
	}
}
