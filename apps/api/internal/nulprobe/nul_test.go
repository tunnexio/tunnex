package nulprobe

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNulByteParam(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("no dsn")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `CREATE TEMP TABLE nulprobe_t (v text)`); err != nil {
		t.Fatal(err)
	}
	v := "\x00"
	_, err = pool.Exec(ctx, `INSERT INTO nulprobe_t (v) VALUES ($1)`, &v)
	t.Logf("INSERT with NUL string -> err = %#v", err)
	if err != nil {
		t.Logf("error string: %s", err.Error())
	}
	// also probe the CASE-expression shape used by CreateRekeyChallenge
	kind := "cert_serial"
	_, err2 := pool.Exec(ctx, `INSERT INTO nulprobe_t (v) VALUES (CASE WHEN $2 = 'cert_serial' THEN $1 END)`, &v, kind)
	t.Logf("CASE insert -> err = %v", err2)
}
