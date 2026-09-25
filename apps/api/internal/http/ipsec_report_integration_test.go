package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Certificate state is injected as supplied by the authenticated listener; this
// exercises identity lookup and persistence, not the TLS handshake itself.
func TestIPsecCapabilityAuthenticatedReportIntegration(t *testing.T) {
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
	name := "tnx_ipsec_report_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

	org, node, other := uuid.New(), uuid.New(), uuid.New()
	serial := new(big.Int).SetBytes(node[:])
	if _, err = pool.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'IPsec report',$2,'10.197.0.0/24')`, org, "report-"+org.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO nodes(id,org_id,name,cert_serial,cert_delivered) VALUES($1,$2,'reporter',$3,true),($4,$2,'untouched',$5,true)`, node, org, hex.EncodeToString(serial.Bytes()), other, "other-"+other.String()); err != nil {
		t.Fatal(err)
	}
	channel := NewAgentChannel(nodes.NewService(pool, nil, nil), nil, nil, nil)
	const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="
	for _, tc := range []struct {
		name, fields string
		version      int
		recovery     int
	}{
		{"recovery supported", `,"ipsec_config_version":1,"ipsec_recovery_version":1`, 1, 1},
		{"recovery no config", `,"ipsec_recovery_version":1`, 0, 0},
		{"recovery future", `,"ipsec_config_version":1,"ipsec_recovery_version":2`, 1, 0},
		{"supported", `,"ipsec_config_version":1`, 1, 0},
		{"legacy clears", ``, 0, 0},
		{"supported again", `,"ipsec_config_version":1`, 1, 0},
		{"negative clears", `,"ipsec_config_version":-1`, 0, 0},
		{"future unknown", `,"ipsec_config_version":2`, 0, 0},
		{"explicit unsupported", `,"ipsec_config_version":0`, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var before time.Time
			if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			body := `{"public_key":"` + key + `","node_id":"` + other.String() + `","ipsec_reported_at":"2099-01-01T00:00:00Z"` + tc.fields + `}`
			req := httptest.NewRequest(http.MethodPost, "/agent/report", strings.NewReader(body)).WithContext(ctx)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: serial}}}
			rec := httptest.NewRecorder()
			channel.report(rec, req)
			if rec.Code != 204 {
				t.Fatalf("report %d: %s", rec.Code, rec.Body.String())
			}
			var after time.Time
			if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&after); err != nil {
				t.Fatal(err)
			}
			var raw []byte
			var received time.Time
			if err := pool.QueryRow(ctx, `SELECT capabilities,policy_reported_at FROM nodes WHERE id=$1`, node).Scan(&raw, &received); err != nil {
				t.Fatal(err)
			}
			caps := nodes.Capabilities(raw)
			if caps.IPsecRecoveryVersion != tc.recovery {
				t.Fatalf("recovery=%d want%d", caps.IPsecRecoveryVersion, tc.recovery)
			}
			if caps.IPsecConfigVersion != tc.version {
				t.Fatalf("capability version=%d want%d", caps.IPsecConfigVersion, tc.version)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			if string(fields["ipsec_config_version"]) != string(rune('0'+tc.version)) {
				t.Fatal("explicit normalized version missing")
			}
			if received.Before(before) || received.After(after) {
				t.Fatal("policy_reported_at must be CP receipt time")
			}
			if _, exists := fields["ipsec_reported_at"]; exists {
				t.Fatal("agent supplied timestamp must not be persisted")
			}

			var untouched bool
			if err := pool.QueryRow(ctx, `SELECT NOT(capabilities ? 'ipsec_config_version') FROM nodes WHERE id=$1`, other).Scan(&untouched); err != nil || !untouched {
				t.Fatal("body identity changed other node")
			}
		})
	}
	req := httptest.NewRequest(http.MethodPost, "/agent/report", strings.NewReader(`{"public_key":"`+key+`","ipsec_config_version":1}`)).WithContext(ctx)
	rec := httptest.NewRecorder()
	channel.report(rec, req)
	if rec.Code != 401 {
		t.Fatalf("anonymous report status%d", rec.Code)
	}
}
