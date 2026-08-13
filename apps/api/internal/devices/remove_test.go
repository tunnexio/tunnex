package devices

import (
	"os"
	"strings"
	"testing"
)

// TestRemoveIsSoftAndRevokedOnly — the two properties that make a housekeeping verb safe here.
//
// ⛔ EVERY FOREIGN KEY INTO `devices` IS `ON DELETE CASCADE`, AND ONE OF THEM IS `ovpn_client_certs`. The
// OpenVPN CRL is literally `SELECT serial FROM ovpn_client_certs WHERE revoked_at IS NOT NULL` — so a HARD
// delete of a revoked device would drop its serial out of the CRL and the credential would start being
// ACCEPTED again.
//
// > **A DELETE THAT CASCADES INTO A REVOCATION LIST IS AN UN-REVOKE WEARING A HOUSEKEEPING VERB.**
//
// A hard delete would also destroy the device's posture history, its telemetry, and any policy rule naming
// it as an agent source. This is a source-reading test because the property lives in the SQL: the statement
// must be an UPDATE of `deleted_at`, never a DELETE.
func TestRemoveIsSoftAndRevokedOnly(t *testing.T) {
	q, err := os.ReadFile("../../db/queries/devices.sql")
	if err != nil {
		t.Fatalf("read devices.sql: %v", err)
	}
	i := strings.Index(string(q), "-- name: SoftDeleteRevokedDevice")
	if i < 0 {
		t.Fatal("SoftDeleteRevokedDevice not found — if it was renamed, carry these properties with it")
	}
	stmt := string(q)[i:]
	if end := strings.Index(stmt[1:], "\n-- name: "); end > 0 {
		stmt = stmt[:end]
	}

	// ⛔ SOFT. A `DELETE FROM devices` here would cascade into the CRL.
	if strings.Contains(strings.ToUpper(stmt), "DELETE FROM DEVICES") {
		t.Fatal("removal must be a soft delete: a hard DELETE cascades into ovpn_client_certs and drops " +
			"the serial out of the CRL, un-revoking the credential on the wire")
	}
	if !strings.Contains(stmt, "SET deleted_at = now()") {
		t.Fatal("removal must set deleted_at — 27 queries in this file already scope `deleted_at IS NULL`")
	}

	// ⛔ REVOKED ONLY, AND IN THE STATEMENT — not in a read-then-write, which a concurrent approve could
	// slip between. Removing an ACTIVE device leaves a live credential with no surface to revoke it from.
	if !strings.Contains(stmt, "status = 'revoked'") {
		t.Fatal("the WHERE clause must carry status = 'revoked'; a read-then-write check is racy and a " +
			"removed-but-active device is a working credential nobody can see")
	}
	// ⚠ And it must be org-scoped, like every other mutation here.
	if !strings.Contains(stmt, "org_id = @org_id") {
		t.Fatal("the statement must be org-scoped")
	}

	// ⚠ ROWS-AFFECTED IS READ. Reporting success for a no-op is how an operator concludes a device is gone
	// when it is still on the roster.
	if !strings.Contains(stmt, ":execrows") {
		t.Fatal("the query must return rows-affected so `not found` and `not revoked` are different answers")
	}

	svc, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"device_not_revoked", "device_not_found"} {
		if !strings.Contains(string(svc), want) {
			t.Fatalf("RemoveRevoked must distinguish the zero-row causes; %q is missing", want)
		}
	}
}
