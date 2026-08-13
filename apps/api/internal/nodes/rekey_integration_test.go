package nodes

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	tcrypto "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/rekey"
)

// rekeyFixture runs the whole re-key path inside ONE transaction that is rolled back.
//
// WHY THAT MATTERS HERE AND NOT ONLY FOR TIDINESS. agentca.LoadOrCreate PERSISTS a CA sealed under the sealer it is
// given, and refuses to regenerate one it cannot decrypt — correctly, since a new CA would orphan every enrolled
// agent. A fixture that committed would therefore leave a CA sealed under a throwaway test key in the shared
// development database, and the next thing to open it — the local control plane, or the next test — would find a CA
// it can never use. Service.withTx runs against s.q when s.pool is nil (service.go), so passing a tx-backed Queries
// puts every write, including Rekey's own transaction, inside this one.
type rekeyFixture struct {
	ctx context.Context
	tx  pgx.Tx
	svc *Service
	org uuid.UUID
}

func seedRekeyFixture(t *testing.T) *rekeyFixture {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	q := sqlc.New(tx)

	key := make([]byte, tcrypto.KeySize)
	_, _ = rand.Read(key)
	sealer, _ := tcrypto.NewSealer(key)
	ca, _, err := agentca.LoadOrCreate(ctx, q, sealer)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}

	org := uuid.New()
	if _, err := tx.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'O',$2)",
		org, "rk-"+org.String()); err != nil {
		t.Fatalf("org: %v", err)
	}

	// pool deliberately NIL — see the type comment: it is what puts Rekey's transaction inside this one.
	svc := &Service{q: q, ca: ca, sealer: sealer}
	return &rekeyFixture{ctx: ctx, tx: tx, svc: svc, org: org}
}

// addExpiredNode seeds a node whose certificate has EXPIRED (so the gone-gate authorizes) with `key` recorded as its
// public key — the shape a gateway that needs recovery is actually in.
func (f *rekeyFixture) addExpiredNode(t *testing.T, name string, pub *rsa.PublicKey) (id uuid.UUID, serial string) {
	t.Helper()
	id, serial = uuid.New(), "serial-"+uuid.NewString()
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.tx.Exec(f.ctx, `
		INSERT INTO nodes (id,org_id,name,cert_serial,cert_public_key,cert_not_after,status,cert_delivered_at)
		VALUES ($1,$2,$3,$4,$5,now() - interval '2 days','active',now() - interval '3 days')`,
		id, f.org, name, serial, base64.StdEncoding.EncodeToString(spki)); err != nil {
		t.Fatalf("seed node: %v", err)
	}
	return id, serial
}

func (f *rekeyFixture) row(t *testing.T, id uuid.UUID) sqlc.Node {
	t.Helper()
	var n sqlc.Node
	if err := f.tx.QueryRow(f.ctx,
		"SELECT cert_serial, cert_public_key, id FROM nodes WHERE id=$1", id).Scan(&n.CertSerial, &n.CertPublicKey, &n.ID); err != nil {
		t.Fatalf("read node: %v", err)
	}
	return n
}

// attempt runs a COMPLETE re-key: challenge, sign, submit. popKey proves possession; csrKey is the key the new
// certificate is issued over.
func (f *rekeyFixture) attempt(t *testing.T, ident RekeyIdentifier, popKey, csrKey *rsa.PrivateKey) error {
	t.Helper()
	nonce, err := f.svc.IssueRekeyChallenge(f.ctx, ident)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "gw"}}, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	sum := sha256.Sum256(rekey.SignedMessage(nonce, csrDER))
	sig, err := rsa.SignPKCS1v15(rand.Reader, popKey, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = f.svc.Rekey(f.ctx, ident, nonce, csrPEM, sig, "0.1.0")
	return err
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func fingerprintOf(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return KeyFingerprint(der)
}

// TestLostResponseDoesNotBrickTheGateway is the whole reason D10 exists, end to end against a real database.
//
// THE SEQUENCE, which is exactly what a dropped connection produces:
//
//  1. the gateway re-keys successfully — the control plane commits a new serial and records the new public key
//  2. the RESPONSE never arrives, so the agent still holds its old (expired) certificate and its old serial
//  3. the agent retries by SERIAL. That serial no longer exists on any row, so it is refused — and would be refused
//     forever, which before D10 meant a join token, a NEW node, a lost site binding and every device re-issued
//  4. the agent retries by the FINGERPRINT of the key it persisted BEFORE submitting — the key the control plane
//     recorded in step 1 — and recovers the SAME node
//
// Step 4 is only possible because the agent writes its pending key to disk before the request goes out
// (loadOrCreatePendingKey) and because the control plane can be asked about a key rather than only a serial.
func TestLostResponseDoesNotBrickTheGateway(t *testing.T) {
	f := seedRekeyFixture(t)
	k1, k2 := rsaKey(t), rsaKey(t)
	id, serial1 := f.addExpiredNode(t, "gw-lost-"+uuid.NewString()[:8], &k1.PublicKey)

	// (1) A successful re-key. The CSR is over k2 — the key the agent persisted before submitting.
	if err := f.attempt(t, RekeyIdentifier{Kind: IdentifierCertSerial, Value: serial1}, k1, k2); err != nil {
		t.Fatalf("the first re-key must succeed: %v", err)
	}
	after := f.row(t, id)
	if after.CertSerial == serial1 {
		t.Fatal("the serial must have moved")
	}
	if got := KeyFingerprintFromStored(*after.CertPublicKey); got != fingerprintOf(t, &k2.PublicKey) {
		t.Fatal("the control plane must now record the key the CSR carried")
	}

	// (2)+(3) The response was lost. Retrying by the OLD serial names a row that no longer exists.
	//
	// Note the certificate is no longer expired on the row — the re-key in (1) issued a valid one — so this refusal
	// could come from the gate rather than the lookup. Either way it is a refusal, and that is the brick: from the
	// agent's side, its identity is simply gone.
	if err := f.attempt(t, RekeyIdentifier{Kind: IdentifierCertSerial, Value: serial1}, k1, k2); !errors.Is(err, ErrRekeyRefused) {
		t.Fatalf("re-keying by a superseded serial must be refused; got %v", err)
	}

	// The row must be UNTOUCHED by the refused attempt. A refusal that mutated something is not a refusal.
	if again := f.row(t, id); again.CertSerial != after.CertSerial {
		t.Fatal("a refused attempt must not change the node's identity")
	}

	// (4) Recovery by fingerprint — WITH THE ROW EXACTLY AS THE LOST RESPONSE LEFT IT.
	//
	// THIS TEST USED TO CHEAT HERE, and review pass 1 #3 caught it. It hand-applied
	//     UPDATE nodes SET cert_not_after = now() - interval '2 days'
	// with a comment claiming that is "what it will be by the time the agent gets here in the field". That is
	// FALSE, and it was the defect wearing the costume of setup: the re-key in step (1) COMMITTED a fresh
	// certificate, so cert_not_after is 48 HOURS IN THE FUTURE — the node reads LIVE, and the gate refused the
	// recovery D10 exists for. The guard fabricated the state that made it pass.
	//
	// So nothing is touched. The row stays as the control plane left it, and recovery must work anyway, through
	// the redelivery carve-out: the caller proves the key the CP records NOW and asks for a certificate over that
	// same key.
	var notAfter time.Time
	if err := f.tx.QueryRow(f.ctx, "SELECT cert_not_after FROM nodes WHERE id=$1", id).Scan(&notAfter); err != nil {
		t.Fatal(err)
	}
	// AND ITS CERTIFICATE HAS NEVER BEEN DELIVERED — the fact that distinguishes a lost response from a live
	// gateway, and the only thing the carve-out is allowed to key on. RekeyNode cleared it in the same statement
	// that replaced the serial (D3 condition 1); a marker that survived the swap would describe the old
	// certificate while naming the new one.
	var delivered bool
	if err := f.tx.QueryRow(f.ctx, "SELECT cert_delivered FROM nodes WHERE id=$1", id).Scan(&delivered); err != nil {
		t.Fatal(err)
	}
	if delivered {
		t.Fatal("re-key must set cert_delivered=false in the same statement that replaces the serial — a marker " +
			"that survived the swap would describe the OLD certificate while naming the new one")
	}
	if !notAfter.After(time.Now()) {
		t.Fatalf("this test is only meaningful while the committed certificate is still VALID — the whole point "+
			"is that the node reads live; cert_not_after=%s", notAfter)
	}

	// The CSR carries k2, the key the control plane recorded in step (1) — redelivery, not rotation.
	fp2 := fingerprintOf(t, &k2.PublicKey)
	if err := f.attempt(t, RekeyIdentifier{Kind: IdentifierKeyFingerprint, Value: fp2}, k2, k2); err != nil {
		t.Fatalf("re-key by the fingerprint of the key the control plane RECORDED must succeed against a row whose "+
			"certificate is still valid — that row is exactly what a lost response leaves behind, and without this "+
			"a single dropped packet costs a gateway its identity for a full certificate lifetime: %v", err)
	}
	recovered := f.row(t, id)
	if recovered.ID != id {
		t.Fatal("recovery must return the SAME node — same site binding, same history")
	}
	if got := KeyFingerprintFromStored(*recovered.CertPublicKey); got != fp2 {
		t.Fatal("redelivery must leave the SAME key on record — rotating here would mean the carve-out issued over " +
			"a key the caller had not proven, which is the one thing it must not do")
	}

	// AND THE ROTATION IT MUST REFUSE: same proof, but asking for a certificate over a DIFFERENT key. The caller
	// holds k2, so they can already be this node — but the carve-out authorizes redelivery only, and a live node
	// must not be re-keyed onto new material by anyone.
	k3 := rsaKey(t)
	if err := f.attempt(t, RekeyIdentifier{Kind: IdentifierKeyFingerprint, Value: fingerprintOf(t, &k3.PublicKey)}, k2, k3); !errors.Is(err, ErrRekeyRefused) {
		t.Fatalf("a fingerprint that is not the recorded key must not resolve; got %v", err)
	}
	if err := f.attempt(t, RekeyIdentifier{Kind: IdentifierKeyFingerprint, Value: fp2}, k2, k3); !errors.Is(err, ErrRekeyRefused) {
		t.Fatalf("proving the current key must NOT authorize issuing over a DIFFERENT key while the node is live — "+
			"that is rotation, not redelivery, and the gate has no business allowing it; got %v", err)
	}
}

// TestBothIdentifiersRefuseIndistinguishably — the ruled condition, red'd.
//
// Six conditions, one answer. If any of these were distinguishable, an unauthenticated caller could learn which
// serials exist, which keys the fleet holds, or that a fingerprint is ambiguous — and D9 spent the node-name option
// specifically to deny that class of question. The refusal is compared as a VALUE (code + message + status), not
// merely as "an error".
func TestBothIdentifiersRefuseIndistinguishably(t *testing.T) {
	f := seedRekeyFixture(t)
	live, liveSerial := f.addExpiredNode(t, "gw-live-"+uuid.NewString()[:8], &rsaKey(t).PublicKey)
	if _, err := f.tx.Exec(f.ctx,
		"UPDATE nodes SET cert_not_after = now() + interval '30 days' WHERE id=$1", live); err != nil {
		t.Fatal(err)
	}
	k := rsaKey(t)
	dup := rsaKey(t)

	// Two nodes recording the SAME public key — a copied state directory plus a second join token. Nothing prevents
	// it, and it makes the fingerprint ambiguous.
	_, dupSerialA := f.addExpiredNode(t, "gw-dup-a-"+uuid.NewString()[:8], &dup.PublicKey)
	f.addExpiredNode(t, "gw-dup-b-"+uuid.NewString()[:8], &dup.PublicKey)

	cases := []struct {
		name  string
		ident RekeyIdentifier
		pop   *rsa.PrivateKey
	}{
		{"unknown serial", RekeyIdentifier{Kind: IdentifierCertSerial, Value: "serial-nobody-has"}, k},
		{"unknown fingerprint", RekeyIdentifier{Kind: IdentifierKeyFingerprint, Value: fingerprintOf(t, &k.PublicKey)}, k},
		{"live node by serial", RekeyIdentifier{Kind: IdentifierCertSerial, Value: liveSerial}, k},
		{"AMBIGUOUS fingerprint", RekeyIdentifier{Kind: IdentifierKeyFingerprint, Value: fingerprintOf(t, &dup.PublicKey)}, dup},
		{"wrong key by serial", RekeyIdentifier{Kind: IdentifierCertSerial, Value: dupSerialA}, k},
		{"unknown identifier kind", RekeyIdentifier{Kind: "node_name", Value: "gw"}, k},
	}
	var first string
	for _, c := range cases {
		err := f.attempt(t, c.ident, c.pop, rsaKey(t))
		if err == nil {
			t.Fatalf("%s: must be refused", c.name)
		}
		if !errors.Is(err, ErrRekeyRefused) {
			t.Fatalf("%s: must be the uniform refusal, got %v", c.name, err)
		}
		if first == "" {
			first = err.Error()
			continue
		}
		if err.Error() != first {
			t.Errorf("%s: refusal text differs from the others — %q vs %q. Any difference is an oracle: a caller "+
				"who can tell an ambiguous fingerprint from an unknown one has learned that two of the fleet's "+
				"gateways share a key", c.name, err.Error(), first)
		}
	}

	// And the ambiguity must not be resolvable by GUESSING which node was meant — neither dup row may be re-keyed
	// through the fingerprint, even though each is individually re-keyable by its serial.
	if err := f.attempt(t, RekeyIdentifier{Kind: IdentifierCertSerial, Value: dupSerialA}, dup, rsaKey(t)); err != nil {
		t.Fatalf("a duplicate-key node must still be recoverable by its own serial: %v", err)
	}
}

// TestGeneratedFingerprintColumnMatchesTheGoldenVector — the THIRD implementation of the digest, asserted.
//
// The lookup matches on a column PostgreSQL computes (migration 0061). Neither Go implementation can be imported by
// SQL, so this is the only place their agreement is observable. If it drifts, re-key-by-fingerprint matches nothing
// and the failure looks exactly like an unrecoverable gateway.
func TestGeneratedFingerprintColumnMatchesTheGoldenVector(t *testing.T) {
	f := seedRekeyFixture(t)
	id := uuid.New()
	if _, err := f.tx.Exec(f.ctx, `
		INSERT INTO nodes (id,org_id,name,cert_serial,cert_public_key,status)
		VALUES ($1,$2,$3,$4,$5,'active')`,
		id, f.org, "gw-golden-"+uuid.NewString()[:8], "serial-"+uuid.NewString(), goldenSPKIB64); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var got *string
	if err := f.tx.QueryRow(f.ctx, "SELECT cert_key_fingerprint FROM nodes WHERE id=$1", id).Scan(&got); err != nil {
		t.Fatalf("read generated column: %v", err)
	}
	if got == nil || *got != goldenFingerprint {
		t.Fatalf("the DATABASE's generated fingerprint disagrees with the golden vector the agent sends.\n got %v\n"+
			"want %s", got, goldenFingerprint)
	}

	// A node with NO recorded key must yield NULL, which matches nothing — the pre-0057 coverage limitation, which
	// D1(a) keeps the join token for. A non-NULL fingerprint over a NULL key would match every other such node.
	bare := uuid.New()
	if _, err := f.tx.Exec(f.ctx, `
		INSERT INTO nodes (id,org_id,name,cert_serial,status) VALUES ($1,$2,$3,$4,'active')`,
		bare, f.org, "gw-bare-"+uuid.NewString()[:8], "serial-"+uuid.NewString()); err != nil {
		t.Fatalf("seed bare: %v", err)
	}
	var bareFP *string
	if err := f.tx.QueryRow(f.ctx, "SELECT cert_key_fingerprint FROM nodes WHERE id=$1", bare).Scan(&bareFP); err != nil {
		t.Fatal(err)
	}
	if bareFP != nil {
		t.Fatalf("a node with no recorded key must have a NULL fingerprint, got %q", *bareFP)
	}
}

// TestAChallengeRoundTripsUnderITSOWNIdentifier — what replaced the rolling-upgrade shim test (review pass 1 #20).
//
// THE SHIM IS GONE, AND SO IS THE TEST THAT VOUCHED FOR IT. Migration 0061 wrote cert_serial alongside identifier
// and read coalesce(identifier, cert_serial), to let a previous-version replica consume a challenge this version
// issued. That version CANNOT EXIST: node_rekey_challenges is created by migration 0058, in the SAME RELEASE. No
// shipped control plane has ever read this table.
//
// It was built because TestMigrationsAreBackwardCompatibleForOneVersion refused a RENAME — a line-level regex over
// migration text with no notion of which tables the previous version knew. Its verdict was taken as authority and
// machinery was built to satisfy it. The old test then asserted, in both directions, that the machinery worked.
//
// What is worth asserting is the behaviour that remains: a challenge is bound to the identifier AND KIND it was
// issued for, and cannot be spent under another.
func TestAChallengeRoundTripsUnderITSOWNIdentifier(t *testing.T) {
	f := seedRekeyFixture(t)
	k := rsaKey(t)
	_, serial := f.addExpiredNode(t, "gw-roll-"+uuid.NewString()[:8], &k.PublicKey)

	nonce, err := f.svc.IssueRekeyChallenge(f.ctx, RekeyIdentifier{Kind: IdentifierCertSerial, Value: serial})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// The WRONG kind must not consume it, even with the right value.
	if _, err := f.svc.q.ConsumeRekeyChallenge(f.ctx, sqlc.ConsumeRekeyChallengeParams{
		Nonce: nonce, Identifier: &serial, IdentifierKind: IdentifierKeyFingerprint,
	}); err == nil {
		t.Fatal("a challenge issued for a SERIAL must not be spendable as a FINGERPRINT — the kind is bound with " +
			"the value precisely so the two cannot be mixed")
	}
	got, err := f.svc.q.ConsumeRekeyChallenge(f.ctx, sqlc.ConsumeRekeyChallengeParams{
		Nonce: nonce, Identifier: &serial, IdentifierKind: IdentifierCertSerial,
	})
	if err != nil {
		t.Fatalf("the identifier it WAS issued for must consume it: %v", err)
	}
	if got.ConsumedAt.Time.IsZero() {
		t.Fatal("consuming must stamp consumed_at — single-use is the replay defence")
	}
	// SINGLE USE: a second attempt with the same nonce must find nothing.
	if _, err := f.svc.q.ConsumeRekeyChallenge(f.ctx, sqlc.ConsumeRekeyChallengeParams{
		Nonce: nonce, Identifier: &serial, IdentifierKind: IdentifierCertSerial,
	}); err == nil {
		t.Fatal("a spent nonce must not be spendable again")
	}
}

// TestADELIVEREDCertificateCannotBeRedelivered — the integration-level REGRESSION RED for the live-node takeover
// (S13.1 D3, introduced by this carve-out's first version and found by the author).
//
// The first predicate keyed on the CALLER'S possession of the recorded key, which a live gateway's key-holder
// also has. Because RekeyNode replaces cert_serial — the column the agent channel authenticates against — that
// authorized DISPLACING a running gateway with nothing but a stolen private key, no certificate needed.
//
// The narrowed predicate is the control plane's own observation: has this certificate ever authenticated? A
// running gateway's has. So the live case is not refused by a check — it is unreachable.
func TestADELIVEREDCertificateCannotBeRedelivered(t *testing.T) {
	f := seedRekeyFixture(t)
	k := rsaKey(t)
	id, _ := f.addExpiredNode(t, "gw-live-"+uuid.NewString()[:8], &k.PublicKey)

	// A LIVE gateway: valid certificate, and it has authenticated — which is what running means.
	if _, err := f.tx.Exec(f.ctx,
		"UPDATE nodes SET cert_not_after = now() + interval '30 days', cert_delivered = true WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	before := f.row(t, id)

	// The attacker holds the node's private key and nothing else. Under the first predicate this succeeded.
	fp := fingerprintOf(t, &k.PublicKey)
	if err := f.attempt(t, RekeyIdentifier{Kind: IdentifierKeyFingerprint, Value: fp}, k, k); !errors.Is(err, ErrRekeyRefused) {
		t.Fatalf("re-keying a LIVE gateway must be refused even by a caller holding its key — otherwise a private "+
			"key stolen without its certificate displaces the running gateway (401 unknown_agent on its next "+
			"request); got %v", err)
	}
	if after := f.row(t, id); after.CertSerial != before.CertSerial {
		t.Fatal("a refused attempt must not move the serial — that IS the displacement")
	}
}

// TestAnENROLLEDNodeIsClosedByDefault — the fail-safe encoding (S13.1 D3 condition 2, extended to new rows).
//
// CreateNode does not mention the delivery column, and neither does any older control-plane replica mid-roll. A
// NULLABLE timestamp made that absence mean UNDELIVERED — the state that OPENS the redelivery carve-out — so
// every freshly enrolled node was exposed from enrolment until its first authenticated request, on every replica.
//
// The boolean's DEFAULT TRUE makes absence mean CLOSED. This red inserts a node exactly as an unaware writer
// would, naming no delivery column at all.
func TestAnENROLLEDNodeIsClosedByDefault(t *testing.T) {
	f := seedRekeyFixture(t)
	k := rsaKey(t)
	id := uuid.New()
	// The columns CreateNode names, and nothing else — the shape an older replica writes.
	if _, err := f.tx.Exec(f.ctx, `
		INSERT INTO nodes (id,org_id,name,cert_serial,agent_version,cert_not_after,cert_public_key)
		VALUES ($1,$2,$3,$4,'0.1.0',now() + interval '48 hours',$5)`,
		id, f.org, "gw-fresh-"+uuid.NewString()[:8], "serial-"+uuid.NewString(),
		base64.StdEncoding.EncodeToString(mustSPKI(t, &k.PublicKey))); err != nil {
		t.Fatal(err)
	}
	var delivered bool
	if err := f.tx.QueryRow(f.ctx, "SELECT cert_delivered FROM nodes WHERE id=$1", id).Scan(&delivered); err != nil {
		t.Fatal(err)
	}
	if !delivered {
		t.Fatal("a writer that does not know the delivery column must land in the CLOSED state — otherwise every " +
			"newly enrolled node, and every node enrolled by an older replica during a roll, is redeliverable " +
			"while live: a fail-open introduced by the fix for a fail-open")
	}

	// And the gate agrees: the carve-out must not authorize this node.
	if err := f.attempt(t, RekeyIdentifier{Kind: IdentifierKeyFingerprint, Value: fingerprintOf(t, &k.PublicKey)}, k, k); !errors.Is(err, ErrRekeyRefused) {
		t.Fatalf("a freshly enrolled, live node must be refused; got %v", err)
	}
}

func mustSPKI(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
