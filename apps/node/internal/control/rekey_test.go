package control

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// rekeyServer is a control plane that RECORDS what the agent sent, so the reds can assert the request rather than
// only the outcome.
// The harness reuses client_test.go's testCA. Before review pass 1 #1 it returned the literal string "CERT" and
// every test passed — which is precisely the defect: the agent verified nothing, so a fixture that certified
// nothing was indistinguishable from a real control plane.

// issueFor signs a leaf over pub, as the control plane would for a submitted CSR.
func (ca *testCA) issueFor(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "gw"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type rekeyServer struct {
	nonce     []byte
	lastBody  map[string]string
	challenge map[string]string // the identifier fields the challenge call carried
	refuse    bool

	ca *testCA // the CA the agent trusts, unless a test swaps it
	// issueOver, when set, is the key the server certifies INSTEAD of the one the CSR carried — the substituted
	// certificate case.
	issueOver *rsa.PublicKey
	// failStatus, when non-zero, is returned by the SUBMIT route instead of a certificate.
	failStatus int
	// throttleFor, when non-zero, answers 429 with that many seconds of Retry-After.
	throttleFor int
	// caInBody is the ca_pem the server ATTACHES to its response. Tests set it to a hostile CA to prove the agent
	// ignores it. Empty = send the real one.
	caInBody []byte
}

func (s *rekeyServer) start(t *testing.T) string {
	t.Helper()
	s.nonce = []byte("server-issued-nonce-0123456789ab")
	if s.ca == nil {
		s.ca = newTestCA(t)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/rekey/challenge", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.challenge = body
		_ = json.NewEncoder(w).Encode(map[string]string{"nonce": base64.StdEncoding.EncodeToString(s.nonce)})
	})
	mux.HandleFunc("/api/v1/agent/rekey", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.lastBody = body
		if s.throttleFor > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(s.throttleFor))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if s.failStatus != 0 {
			w.WriteHeader(s.failStatus)
			return
		}
		if s.refuse {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// Sign the key the CSR actually carried, exactly as the control plane does — unless a test substitutes one.
		blk, _ := pem.Decode([]byte(body["csr"]))
		csr, cerr := x509.ParseCertificateRequest(blk.Bytes)
		if cerr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		pub := csr.PublicKey.(*rsa.PublicKey)
		if s.issueOver != nil {
			pub = s.issueOver
		}
		caBody := s.caInBody
		if len(caBody) == 0 {
			caBody = s.ca.pem
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"cert_pem": string(s.ca.issueFor(t, pub)), "ca_pem": string(caBody),
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func testKey(t *testing.T) []byte {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pubOf(t *testing.T, keyPEM []byte) *rsa.PublicKey {
	t.Helper()
	k, err := parseRSAKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &k.PublicKey
}

// TestRekeyIssuesOverThePENDINGKeyNotAFreshOne — the convergence property (S13.1 D10).
//
// The CSR must carry the key the CALLER persisted, because that is the key the control plane will record and the key
// the agent will have to prove possession of if this response is lost. If Rekey minted its own, every retry would
// record a different key and the agent would end up proving possession of one the control plane never saw.
func TestRekeyIssuesOverThePENDINGKeyNotAFreshOne(t *testing.T) {
	srv := &rekeyServer{}
	url := srv.start(t)
	pending, old := testKey(t), testKey(t)

	if _, err := Rekey(t.Context(), url, Identifier{CertSerial: "S1"}, pending, old, srv.ca.pem, "0.1.0", "gw"); err != nil {
		t.Fatalf("rekey: %v", err)
	}

	blk, _ := pem.Decode([]byte(srv.lastBody["csr"]))
	if blk == nil {
		t.Fatal("no CSR was sent")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("CSR key is not RSA")
	}
	if got.N.Cmp(pubOf(t, pending).N) != 0 {
		t.Fatal("the CSR must be over the PENDING key the caller persisted. Minting a fresh key here means a lost " +
			"response leaves the agent unable to prove possession of what the control plane recorded — the brick " +
			"D10 removes, reintroduced one layer down")
	}
}

// TestProofIsSignedByThePoPKeyAndBoundToTheCSR — the two keys have different jobs and must not be conflated: the
// pending key is what the certificate is issued OVER, the PoP key is what says who is asking.
func TestProofIsSignedByThePoPKeyAndBoundToTheCSR(t *testing.T) {
	srv := &rekeyServer{}
	url := srv.start(t)
	pending, old := testKey(t), testKey(t)

	if _, err := Rekey(t.Context(), url, Identifier{CertSerial: "S1"}, pending, old, srv.ca.pem, "0.1.0", "gw"); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(srv.lastBody["signature"])
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(srv.lastBody["csr"]))
	sum := sha256.Sum256(signedMessage(srv.nonce, blk.Bytes))

	if err := rsa.VerifyPKCS1v15(pubOf(t, old), crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("the proof must verify against the PoP key over (nonce || CSR DER): %v", err)
	}
	if rsa.VerifyPKCS1v15(pubOf(t, pending), crypto.SHA256, sum[:], sig) == nil {
		t.Fatal("the proof must NOT be signed by the pending key when a separate PoP key was supplied — the control " +
			"plane verifies against the key it RECORDED, and signing with the new one would be a proof of nothing")
	}
}

// TestIdentifierIsCarriedOnBOTHRoundTRIPS — the nonce is bound to its identifier server-side, so a challenge taken
// out under one and spent under the other is refused. Sending the identifier only on the submit (or only on the
// challenge) would make fingerprint recovery fail in a way that looks like a refusal.
func TestIdentifierIsCarriedOnBOTHRoundTRIPS(t *testing.T) {
	fp := "1e98cb7cd8f91d59b2f90727f5543f9c9e5413332b160c93534c283ea3bdba94"
	for _, c := range []struct {
		name  string
		ident Identifier
		field string
		want  string
	}{
		{"serial", Identifier{CertSerial: "S1"}, "cert_serial", "S1"},
		{"fingerprint", Identifier{KeyFingerprint: fp}, "key_fingerprint", fp},
	} {
		srv := &rekeyServer{}
		url := srv.start(t)
		pending := testKey(t)
		if _, err := Rekey(t.Context(), url, c.ident, pending, pending, srv.ca.pem, "0.1.0", "gw"); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if srv.challenge[c.field] != c.want {
			t.Errorf("%s: challenge carried %v, want %s=%s", c.name, srv.challenge, c.field, c.want)
		}
		if srv.lastBody[c.field] != c.want {
			t.Errorf("%s: submit carried %v, want %s=%s", c.name, srv.lastBody, c.field, c.want)
		}
		// EXACTLY ONE identifier on the wire: the control plane refuses a request carrying both, so sending an empty
		// second field would have to be handled as absent — a dependency on the server's emptiness semantics that
		// this simply does not create.
		other := "key_fingerprint"
		if c.field == other {
			other = "cert_serial"
		}
		if _, present := srv.lastBody[other]; present {
			t.Errorf("%s: the unused identifier must be ABSENT from the body, not empty — the control plane refuses "+
				"a request that names two identities", c.name)
		}
	}
}

// TestRefusalIsNotThrottled — the review-#10 distinction, kept at the boundary between the two identities: a 403
// refusal and a 429 must remain different errors, because the agent's retry behaviour and its diagnosis differ.
func TestRefusalIsNotThrottled(t *testing.T) {
	srv := &rekeyServer{refuse: true}
	url := srv.start(t)
	pending := testKey(t)
	_, err := Rekey(t.Context(), url, Identifier{CertSerial: "S1"}, pending, pending, srv.ca.pem, "0.1.0", "gw")
	if !errors.Is(err, ErrRekeyRefused) {
		t.Fatalf("a 403 must be ErrRekeyRefused, got %v", err)
	}
	if errors.Is(err, ErrRekeyThrottled) {
		t.Fatal("a refusal must never read as a throttle")
	}
}

var _ = rand.Reader

// TestHostileResponderCannotReplaceTheTrustAnchor — review pass 1 #1 (CRITICAL), R1.
//
// THE ATTACK IT CLOSES. Re-key runs over TUNNEX_API_URL, which defaults to plain HTTP, so the responder is
// unauthenticated and anyone on the path can be it. The agent used to write the response's ca_pem into ca.pem —
// the ONLY RootCAs its mTLS control channel has — so one answered request bought permanent control-plane
// impersonation: every subsequent peer set, policy artifact, route and DNS forward would come from the attacker.
//
// The fix is refusal, not detection: the anchor is an INPUT, the issued certificate must chain to it, and no CA
// is returned to be written. An attacker who answers can now only make recovery fail — which they could already
// do by dropping the request.
func TestHostileResponderCannotReplaceTheTrustAnchor(t *testing.T) {
	realCA := newTestCA(t)
	attackerCA := newTestCA(t)

	// The server is the attacker: it signs with ITS OWN CA and attaches its own ca_pem, exactly as a real control
	// plane would attach the real one.
	srv := &rekeyServer{ca: attackerCA}
	url := srv.start(t)
	pending := testKey(t)

	cert, err := Rekey(t.Context(), url, Identifier{CertSerial: "S1"}, pending, pending, realCA.pem, "0.1.0", "gw")
	if !errors.Is(err, ErrIssuedCertUntrusted) {
		t.Fatalf("a certificate signed by a CA this agent does not trust must be REFUSED, got err=%v", err)
	}
	if cert != nil {
		t.Fatal("nothing may be returned for the caller to write — a refusal that still hands back material is " +
			"one careless caller away from being no refusal at all")
	}
	if errors.Is(err, ErrRekeyRefused) {
		t.Fatal("an untrusted response must NOT read as a control-plane refusal: the CP never answered, and " +
			"printing its remedy would talk an operator into discarding a working identity")
	}
}

// TestResponseCAIsIGNOREDEvenWhenTheCertIsGenuine — the narrower half, and the one a partial fix would miss.
//
// A responder that somehow holds a genuine certificate could still attach a hostile ca_pem. The agent must not
// write it, must not return it, and must not treat its presence as meaningful at all.
func TestResponseCAIsIGNOREDEvenWhenTheCertIsGenuine(t *testing.T) {
	realCA := newTestCA(t)
	hostile := newTestCA(t)
	srv := &rekeyServer{ca: realCA, caInBody: hostile.pem}
	url := srv.start(t)
	pending := testKey(t)

	cert, err := Rekey(t.Context(), url, Identifier{CertSerial: "S1"}, pending, pending, realCA.pem, "0.1.0", "gw")
	if err != nil {
		t.Fatalf("a genuine certificate must still be accepted: %v", err)
	}
	if cert == nil {
		t.Fatal("the issued certificate must be returned")
	}
	// The signature of the fix: Rekey has NO channel through which a CA can reach the caller.
	if got := srv.lastBody["ca_pem"]; got != "" {
		t.Log("(the server did attach a ca_pem; the point is that the agent has nowhere to put it)")
	}
}

// TestIssuedCertMustCertifyTHISAgentsKey — the second property, independent of provenance.
//
// A certificate that chains correctly but certifies a DIFFERENT key would be promoted into key.pem's place,
// leaving a cert/key pair that does not match — an identity this agent cannot use and, at boot, cannot explain.
func TestIssuedCertMustCertifyTHISAgentsKey(t *testing.T) {
	ca := newTestCA(t)
	someoneElse := testKey(t)
	otherPub := pubOf(t, someoneElse)

	srv := &rekeyServer{ca: ca, issueOver: otherPub}
	url := srv.start(t)
	pending := testKey(t)

	if _, err := Rekey(t.Context(), url, Identifier{CertSerial: "S1"}, pending, pending, ca.pem, "0.1.0", "gw"); !errors.Is(err, ErrIssuedCertUntrusted) {
		t.Fatalf("a certificate over a key this agent did not ask for must be refused, got %v", err)
	}
}

// TestNoAnchorOnDiskIsRefusedNotAssumed — "I cannot check" must never resolve to "it is fine".
func TestNoAnchorOnDiskIsRefusedNotAssumed(t *testing.T) {
	srv := &rekeyServer{}
	url := srv.start(t)
	pending := testKey(t)

	if _, err := Rekey(t.Context(), url, Identifier{CertSerial: "S1"}, pending, pending, nil, "0.1.0", "gw"); err == nil {
		t.Fatal("with no trusted CA on disk there is nothing to verify against, and re-key must refuse rather " +
			"than accept whatever answers")
	}
}

// TestTransportFaultsAreNOTRefusals — review pass 1 #10 and pass 3 claims 9/10/14.
//
// The refusal BODY is uniform by design and says nothing; the STATUS is the only signal the agent may act on. Every
// non-200 used to become ErrRekeyRefused, so a control-plane restart, a proxy 502 or a dropped connection all
// printed "mint a join token" — and acting on that during an outage DISCARDS a working identity, creating a new
// node whose site binding is gone and whose devices need re-issuing. The remedy for a refusal is the worst possible
// response to a blip.
func TestTransportFaultsAreNOTRefusals(t *testing.T) {
	for _, status := range []int{500, 502, 503, 404, 400} {
		srv := &rekeyServer{failStatus: status}
		url := srv.start(t)
		pending := testKey(t)
		_, err := Rekey(t.Context(), url, Identifier{CertSerial: "S1"}, pending, pending, srv.ca.pem, "0.1.0", "gw")
		if errors.Is(err, ErrRekeyRefused) {
			t.Fatalf("status %d must NOT read as a control-plane refusal — nothing decided anything", status)
		}
		if !errors.Is(err, ErrRekeyTransient) {
			t.Fatalf("status %d must be transient, got %v", status, err)
		}
	}
	// 403 IS the control plane deciding, and must stay distinguishable.
	srv := &rekeyServer{refuse: true}
	url := srv.start(t)
	pending := testKey(t)
	if _, err := Rekey(t.Context(), url, Identifier{CertSerial: "S1"}, pending, pending, srv.ca.pem, "0.1.0", "gw"); !errors.Is(err, ErrRekeyRefused) {
		t.Fatalf("403 must remain a refusal, got %v", err)
	}
	// An unreachable endpoint is transient too — nothing answered at all.
	if _, err := Rekey(t.Context(), "http://127.0.0.1:1", Identifier{CertSerial: "S1"}, pending, pending, srv.ca.pem, "0.1.0", "gw"); !errors.Is(err, ErrRekeyTransient) {
		t.Fatalf("an unreachable control plane must be transient, got %v", err)
	}
}

// TestRetryAfterIsCARRIEDNotJustPrinted — pass 3 claim 10.
//
// Retry-After was parsed, formatted into the error STRING, and discarded. The agent then retried on its own floor
// while the log printed the server's number, so the two disagreed in writing and the operator had no way to know
// which one the code used.
func TestRetryAfterIsCARRIEDNotJustPrinted(t *testing.T) {
	srv := &rekeyServer{throttleFor: 60}
	url := srv.start(t)
	pending := testKey(t)

	_, err := Rekey(t.Context(), url, Identifier{CertSerial: "S1"}, pending, pending, srv.ca.pem, "0.1.0", "gw")
	if !errors.Is(err, ErrRekeyThrottled) {
		t.Fatalf("429 must be a throttle, got %v", err)
	}
	if got := RetryAfterOf(err); got != 60*time.Second {
		t.Fatalf("the server's Retry-After must be RECOVERABLE from the error, not only rendered into its text; "+
			"got %v", got)
	}
}
