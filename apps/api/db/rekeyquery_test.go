package db_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRekeyQueryCannotResurrect — the STRUCTURAL half of the amended D3.
//
// The gate refuses to authorize re-key for a revoked node. This asserts the stronger property: even if a future
// caller reached the query without the gate, the statement itself cannot bring a revoked node back, because it does
// not mention `status` or `revoked_at` at all.
//
// WHY THAT MATTERS MORE THAN THE GATE. The attack the amendment closed runs entirely through legitimate-looking
// code: steal a gateway's state volume (its private key) → the operator revokes the gateway → the attacker proves
// possession of the stolen key → if anything sets status back to 'active', the attacker holds a live gateway with
// that node's id, site binding and policy. Revocation defeated by the credential it was invoked against.
//
// A gate can be bypassed by a new call path. A statement that never references the columns cannot resurrect
// anything down ANY path — construction over convention, the same instinct as RekeyAuthorized having no liveness
// parameter to pass.
func TestRekeyQueryCannotResurrect(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("queries", "nodes.sql"))
	if err != nil {
		t.Fatal(err)
	}
	q := queryBlock(string(raw), "RekeyNode")
	if q == "" {
		t.Fatal("RekeyNode query not found — the guard would vouch for nothing")
	}

	// Statements only: this query's comment explains the reasoning at length and names both columns while doing so.
	// Matching the prose would be matching a coincidence of the text rather than the property (docs/laws.md).
	var stmt strings.Builder
	for _, line := range strings.Split(q, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		stmt.WriteString(" " + line)
	}
	sql := strings.ToLower(stmt.String())

	// The SET clause is where resurrection would live. Split there so the status guard in WHERE — which is
	// required — is not mistaken for a write.
	setClause := sql
	if i := strings.Index(sql, "where"); i >= 0 {
		setClause = sql[:i]
	}
	for _, col := range []string{"status", "revoked_at"} {
		if strings.Contains(setClause, col) {
			t.Errorf("RekeyNode must NOT write %q. Re-key must be INCAPABLE of un-revoking a node, not merely "+
				"forbidden from it: a stolen state volume plus a revocation is the attack this closes, and a gate "+
				"can be bypassed by a future call path while a statement that never references the column cannot "+
				"resurrect anything down any path", col)
		}
	}

	// And the WHERE clause must still refuse a revoked row outright — defence in depth for the same property.
	//
	// PARSED, NOT SUBSTRING-MATCHED (review pass 1 #19). The guard used to assert that the text
	// `status = 'active'` appeared SOMEWHERE, which a WHERE clause of `id = $1 OR status = 'active'` satisfies
	// perfectly while re-keying every active node in the fleet. The guard's own docstring claimed it proved the
	// filter "holds even without the gate"; it proved the characters were present.
	//
	// So: isolate the WHERE clause, require the status filter to be AND-ed, and refuse a disjunction outright.
	where := sql[strings.Index(sql, "where "):]
	if i := strings.Index(where, "returning"); i > 0 {
		where = where[:i]
	}
	if strings.Contains(where, " or ") {
		t.Errorf("RekeyNode's WHERE must not contain a disjunction — one OR turns a guarded update into a "+
			"fleet-wide one, and every substring this guard checks would still be present. Got: %q", where)
	}
	if !strings.Contains(where, "and status = 'active'") {
		t.Errorf("RekeyNode must be guarded on AND status = 'active', so a revoked row cannot be re-keyed even if "+
			"a caller reaches this query without consulting RekeyAuthorized. Got: %q", where)
	}
	// The identity must be PRESERVED, not reassigned — D2's replace-in-place. Keyed on id, and on the OLD serial
	// so a stale request cannot rotate a key that has already moved on.
	if !strings.Contains(sql, "where id = $1") || !strings.Contains(sql, "cert_serial = $6") {
		t.Error("RekeyNode must key on the node id AND the old cert serial: the id is what makes this a " +
			"replace-in-place rather than a new node, and the old serial makes a stale request fail rather than " +
			"rotate a key that has already changed")
	}
}
