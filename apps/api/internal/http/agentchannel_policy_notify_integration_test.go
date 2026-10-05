package http

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// The injected certificate state is what the mTLS listener supplies. Use the
// real node service and a separate database read in the callback to prove that
// notification follows persistence, with identity and freshness owned by the API.
func TestAgentPolicyReportNotifyPostgresContract(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, otherOrg := uuid.New(), uuid.New()
	reporter, other, revoked, inactive := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	serial := func(id uuid.UUID) *big.Int { return new(big.Int).SetBytes(id[:]) }
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr)
		VALUES($1,'policy report',$2,'10.99.0.0/24'),($3,'other policy report',$4,'10.98.0.0/24')`,
		org, "policy-report-"+org.String(), otherOrg, "policy-report-"+otherOrg.String()); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		id, org      uuid.UUID
		name, status string
		revoked      bool
	}{
		{reporter, org, "reporter", "active", false},
		{other, otherOrg, "body-selected node", "active", false},
		{revoked, org, "revoked reporter", "revoked", true},
		// The node status domain is active/revoked. A missing revocation
		// timestamp must not let an inactive status authenticate.
		{inactive, org, "inactive reporter", "revoked", false},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO nodes(id,org_id,name,status,cert_serial,cert_delivered,revoked_at,policy_reported_at)
			VALUES($1,$2,$3,$4,$5,true,CASE WHEN $6 THEN clock_timestamp() ELSE NULL END,'2000-01-01T00:00:00Z')`,
			row.id, row.org, row.name, row.status, hex.EncodeToString(serial(row.id).Bytes()), row.revoked); err != nil {
			t.Fatal(err)
		}
	}
	const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="
	hash := strings.Repeat("a", 64)
	body := fmt.Sprintf(`{"public_key":%q,"endpoint":"127.0.0.1:51820","policy_version":1,"policy_hash":%q,"node_id":%q,"org_id":%q,"policy_reported_at":"2099-01-01T00:00:00Z"}`,
		key, hash, other.String(), otherOrg.String())
	request := func(body string, certSerial *big.Int) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/agent/report", strings.NewReader(body)).WithContext(ctx)
		if certSerial != nil {
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: certSerial}}}
		}
		return req
	}
	report := func(channel *AgentChannel, req *http.Request) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		channel.report(response, req)
		return response
	}
	newChannel := func() *AgentChannel { return NewAgentChannel(nodes.NewService(pool, nil, nil), nil, nil, nil) }

	t.Run("persisted certificate-selected evidence before notification", func(t *testing.T) {
		var before time.Time
		if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		channel := newChannel()
		response := httptest.NewRecorder()
		notifications := 0
		channel.SetPolicyReportNotify(func() {
			notifications++
			if response.Code == http.StatusNoContent {
				t.Error("report response preceded notification")
			}
			var gotOrg uuid.UUID
			var gotKey string
			var capabilities []byte
			var received, serverNow time.Time
			if err := pool.QueryRow(ctx, `SELECT org_id,wg_public_key,capabilities,policy_reported_at,clock_timestamp()
				FROM nodes WHERE id=$1`, reporter).Scan(&gotOrg, &gotKey, &capabilities, &received, &serverNow); err != nil {
				t.Fatal(err)
			}
			caps := nodes.Capabilities(capabilities)
			if gotOrg != org || gotKey != key || caps.PolicyHash != hash || caps.PolicyVersion != 1 {
				t.Fatalf("notification preceded exact certificate-selected persistence: org=%s key=%s hash=%s version=%d", gotOrg, gotKey, caps.PolicyHash, caps.PolicyVersion)
			}
			if received.Before(before) || received.After(serverNow) {
				t.Fatal("policy_reported_at was not the server receipt time")
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(capabilities, &fields); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"node_id", "org_id", "policy_reported_at"} {
				if _, exists := fields[field]; exists {
					t.Fatalf("agent-supplied %s entered capabilities", field)
				}
			}
			var untouched bool
			if err := pool.QueryRow(ctx, `SELECT org_id=$2 AND wg_public_key='' AND capabilities='{}'::jsonb
				AND policy_reported_at='2000-01-01T00:00:00Z'::timestamptz FROM nodes WHERE id=$1`, other, otherOrg).Scan(&untouched); err != nil || !untouched {
				t.Fatalf("body-selected node changed before notification: untouched=%t err=%v", untouched, err)
			}
		})
		channel.report(response, request(body, serial(reporter)))
		if response.Code != http.StatusNoContent || notifications != 1 {
			t.Fatalf("report status=%d notifications=%d: %s", response.Code, notifications, response.Body.String())
		}
	})

	t.Run("nil notification preserves report", func(t *testing.T) {
		channel := newChannel()
		channel.SetPolicyReportNotify(nil)
		response := report(channel, request(body, serial(reporter)))
		if response.Code != http.StatusNoContent {
			t.Fatalf("nil notification report status=%d: %s", response.Code, response.Body.String())
		}
	})

	var previousCapabilities []byte
	var previousReport time.Time
	if err := pool.QueryRow(ctx, `SELECT capabilities,policy_reported_at FROM nodes WHERE id=$1`, reporter).Scan(&previousCapabilities, &previousReport); err != nil {
		t.Fatal(err)
	}
	assertUnchanged := func(t *testing.T) {
		t.Helper()
		var capabilities []byte
		var received time.Time
		if err := pool.QueryRow(ctx, `SELECT capabilities,policy_reported_at FROM nodes WHERE id=$1`, reporter).Scan(&capabilities, &received); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(capabilities, previousCapabilities) || !received.Equal(previousReport) {
			t.Fatal("rejected report changed persisted policy evidence")
		}
	}
	channel := newChannel()
	notifications := 0
	channel.SetPolicyReportNotify(func() { notifications++ })
	for _, tc := range []struct {
		name, body string
		serial     *big.Int
		emptyTLS   bool
		status     int
	}{
		{"malformed body", `{"public_key":`, serial(reporter), false, http.StatusBadRequest},
		{"missing key", `{}`, serial(reporter), false, http.StatusBadRequest},
		{"empty key", `{"public_key":""}`, serial(reporter), false, http.StatusBadRequest},
		{"invalid key", `{"public_key":"not-a-wireguard-key"}`, serial(reporter), false, http.StatusBadRequest},
		{"zero key", `{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`, serial(reporter), false, http.StatusBadRequest},
		{"invalid endpoint", `{"public_key":"` + key + `","endpoint":"bad host:51820"}`, serial(reporter), false, http.StatusBadRequest},
		{"missing certificate", body, nil, false, http.StatusUnauthorized},
		{"empty certificate chain", body, nil, true, http.StatusUnauthorized},
		{"unknown certificate", body, big.NewInt(1), false, http.StatusUnauthorized},
		{"revoked certificate", body, serial(revoked), false, http.StatusUnauthorized},
		{"inactive certificate without revocation timestamp", body, serial(inactive), false, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := request(tc.body, tc.serial)
			if tc.emptyTLS {
				req.TLS = &tls.ConnectionState{}
			}
			response := report(channel, req)
			if response.Code != tc.status || notifications != 0 {
				t.Fatalf("rejected report status=%d want=%d notifications=%d: %s", response.Code, tc.status, notifications, response.Body.String())
			}
			assertUnchanged(t)
		})
	}

	t.Run("failed persistence does not notify", func(t *testing.T) {
		// This trigger belongs only to the disposable fixture database. Fail
		// the report's actual write after authentication and validation succeed.
		if _, err := pool.Exec(ctx, `CREATE FUNCTION fail_policy_report_fixture() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'policy report fixture persistence failure'; END $$;
			CREATE TRIGGER fail_policy_report_fixture BEFORE UPDATE OF capabilities ON nodes
			FOR EACH ROW EXECUTE FUNCTION fail_policy_report_fixture()`); err != nil {
			t.Fatal(err)
		}
		changed := strings.Replace(body, hash, strings.Repeat("b", 64), 1)
		response := report(channel, request(changed, serial(reporter)))
		if response.Code != http.StatusInternalServerError || notifications != 0 {
			t.Fatalf("failed persistence status=%d notifications=%d: %s", response.Code, notifications, response.Body.String())
		}
		assertUnchanged(t)
	})
}
