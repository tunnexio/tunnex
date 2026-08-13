package control

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// ErrRekeyRefused is what the control plane's uniform refusal looks like from here.
//
// The CP deliberately does not say WHY (a live node, an unknown serial, a spent nonce and a wrong key are
// indistinguishable, so the endpoint cannot be used as an oracle). So the agent must not try to interpret the
// refusal — it reports what it knows LOCALLY instead, which is the only honest thing it can say.
var ErrRekeyRefused = errors.New("control plane refused the re-key")

// ErrRekeyThrottled is DISTINCT from a refusal, and the distinction is the point (review #10).
//
// A refusal means "this will never work" — the node is revoked, or its key predates key recording — and the right
// response is to back off toward the hour ceiling and tell the operator to mint a join token. A 429 means "not
// right now", and treating it as a refusal defeats the honest-diagnosis property this slice was built around: the
// agent would double its backoff toward an hour and print a most-likely-cause pointing at revocation, for what is
// purely a rate limit. Throttled means retry SOONER and say so.
var ErrRekeyThrottled = errors.New("control plane throttled the re-key attempt")

// ErrRekeyTransient is a fault that says NOTHING about whether this gateway can recover: a connection refused, a
// DNS failure, a 5xx, a body that would not decode.
//
// It exists because conflating it with a refusal is destructive, not merely imprecise. A refusal makes the agent
// print "mint a join token" — and acting on that during a control-plane blip DISCARDS a working identity, creating
// a new node whose site binding is gone and whose devices need re-issuing. The remedy for a refusal is the worst
// possible response to an outage.
var ErrRekeyTransient = errors.New("the re-key attempt did not complete")

// throttled carries the server's Retry-After so the caller can honour it instead of guessing. Before this, the
// value was parsed, formatted into an error STRING, and thrown away — the agent then retried on its own floor
// while the log printed the server's number, so the two disagreed in writing.
type throttled struct{ after time.Duration }

func (t throttled) Error() string {
	if t.after > 0 {
		return ErrRekeyThrottled.Error() + " (retry after " + t.after.String() + ")"
	}
	return ErrRekeyThrottled.Error()
}
func (t throttled) Is(target error) bool { return target == ErrRekeyThrottled }

// RetryAfterOf returns the server-requested delay carried by a throttle error, or 0 when there is none.
func RetryAfterOf(err error) time.Duration {
	var t throttled
	if errors.As(err, &t) {
		return t.after
	}
	return 0
}

// retryAfter reads the server's Retry-After when it is a plain seconds value, which is what the throttle sends.
// Returns 0 when absent or unparseable — the caller then picks its own short delay rather than guessing long.
func retryAfter(resp *http.Response) time.Duration {
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 && secs < 3600 {
			return time.Duration(secs) * time.Second
		}
	}
	return 0
}

// Identifier is how this agent names itself to an endpoint that cannot authenticate it (S13.1 D10).
//
// EXACTLY ONE of the two is set. The serial is what an agent normally knows; the fingerprint is what it still knows
// after a LOST RESPONSE, when the control plane has moved to a serial this agent never received. See PendingKey.
type Identifier struct {
	CertSerial     string
	KeyFingerprint string
}

func (i Identifier) fields() map[string]string {
	if i.KeyFingerprint != "" {
		return map[string]string{"key_fingerprint": i.KeyFingerprint}
	}
	return map[string]string{"cert_serial": i.CertSerial}
}

// Describe names the identifier for logs, without implying the CP said anything about it.
func (i Identifier) Describe() string {
	if i.KeyFingerprint != "" {
		return "key_fingerprint " + i.KeyFingerprint[:min(12, len(i.KeyFingerprint))]
	}
	return "cert_serial " + i.CertSerial
}

// GenerateKey mints a fresh RSA-2048 private key, WITHOUT a CSR.
//
// Separate from GenerateKeyAndCSR because re-key must PERSIST the new key BEFORE it submits anything. A key that
// exists only in memory when the request goes out is a key this agent cannot prove possession of if the response is
// lost — which is precisely how a dropped packet used to cost a gateway its identity.
func GenerateKey() (keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), nil
}

// KeyFingerprintFromPEM computes the identifier for a private key's PUBLIC half: SHA-256 over the SPKI DER,
// lowercase hex.
//
// PINNED TO A GOLDEN VECTOR, in a test in this module and in the control plane's (nodes.KeyFingerprint) and in an
// integration test against the database's generated column. Three implementations of one digest, in two Go modules
// that cannot import each other plus one in SQL — so they agree on purpose rather than by luck. If you change this,
// the golden fails in all three places, which is the point.
func KeyFingerprintFromPEM(keyPEM []byte) (string, error) {
	k, err := parseRSAKey(keyPEM)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return "", err
	}
	return KeyFingerprintFromSPKI(der), nil
}

// KeyFingerprintFromSPKI is the digest itself, separated out so a test can pin it to a golden PUBLIC key without a
// private key ever entering the repository. Over the DER, not over any text encoding of it: a key's identity must not
// depend on how it was written down.
func KeyFingerprintFromSPKI(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	return hex.EncodeToString(sum[:])
}

// csrForKey builds a CSR over an EXISTING key, rather than minting a new one.
func csrForKey(keyPEM []byte, commonName string) (csrPEM []byte, err error) {
	k, err := parseRSAKey(keyPEM)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// Rekey recovers an identity whose certificate has expired, by proving possession of the keypair the control plane
// already recorded for it (S13.1).
//
// It runs over the PUBLIC API listener, not the mTLS agent channel — necessarily, because the certificate that
// would authenticate there is the thing that has expired.
//
// Two round trips, and both are required: the nonce makes a captured request unreplayable, and signing over
// (nonce ‖ CSR DER) binds the proof to this exact request so a captured proof cannot be paired with someone else's
// CSR.
//
// THE CALLER OWNS THE NEW KEY, and that is a correctness requirement rather than an API preference. The pending key
// must be on disk BEFORE the request goes out, so a lost response leaves this agent able to prove possession of the
// key the control plane just recorded. Rekey therefore takes the pending key rather than minting one.
//
// popKeyPEM is whichever key the control plane RECORDED for this node — the expired certificate's key when
// identifying by serial, or the pending key itself when identifying by its fingerprint after a lost response.
//
// THE ANCHOR IS AN INPUT, NEVER AN OUTPUT (review pass 1 #1, R1). This runs over the PUBLIC listener, which ships
// as plain HTTP (TUNNEX_API_URL defaults to http://api:8080) — so the responder is UNAUTHENTICATED and anyone on
// the path can be it. Writing a CA from that response would replace the only RootCAs the mTLS control channel
// has, and an attacker who answered once would own every subsequent desired state: peers, AllowedIPs, policy,
// routes, DNS. So `trustedCAPEM` comes IN, the issued certificate must CHAIN TO IT, and no CA comes out.
//
// What that trades: an attacker who answers can make recovery FAIL. They could already do that by dropping the
// request, so the capability is not new — whereas anchor replacement was permanent impersonation. Refusing is
// strictly the better failure.
//
// CA ROTATION DOES NOT RIDE THIS PATH (ruled). If it is ever needed it gets its own authenticated mechanism;
// this defect existed because a recovery path was quietly doing a rotation path's job.
func Rekey(ctx context.Context, apiURL string, ident Identifier, pendingKeyPEM, popKeyPEM, trustedCAPEM []byte, agentVersion, commonName string) (certPEM []byte, err error) {
	if len(trustedCAPEM) == 0 {
		// No anchor means nothing to verify against, and "I cannot check" must never resolve to "it is fine".
		return nil, errors.New("no trusted CA on disk to verify the issued certificate against")
	}
	popKey, err := parseRSAKey(popKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("stored key unusable: %w", err)
	}

	// The CSR is over the PENDING key — fresh material, minted and persisted by the caller before this call. The
	// proving key's only job is to say who is asking; when the two are the same key, this is a retry re-asserting an
	// identity the control plane may already hold, which is what makes repeated lost responses CONVERGE instead of
	// walking the identity forward on every attempt.
	csrPEM, err := csrForKey(pendingKeyPEM, commonName)
	if err != nil {
		return nil, err
	}
	csrBlk, _ := pem.Decode(csrPEM)
	if csrBlk == nil {
		return nil, errors.New("generated CSR is not PEM")
	}

	nonce, err := rekeyChallenge(ctx, apiURL, ident)
	if err != nil {
		return nil, err
	}

	// The signed message must match the control plane's construction exactly. ONE construction on this side, in
	// signedMessage below, so the agent's own test cannot pin a private copy of it (pass-3 #43).
	msg := signedMessage(nonce, csrBlk.Bytes)
	sum := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, popKey, crypto.SHA256, sum[:])
	if err != nil {
		return nil, err
	}

	fields := ident.fields()
	fields["nonce"] = base64.StdEncoding.EncodeToString(nonce)
	fields["csr"] = string(csrPEM)
	fields["signature"] = base64.StdEncoding.EncodeToString(sig)
	fields["agent_version"] = agentVersion
	body, _ := json.Marshal(fields)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/api/v1/agent/rekey", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		// A transport fault is NOT a refusal: nothing answered, so nothing was decided.
		return nil, fmt.Errorf("%w: %v", ErrRekeyTransient, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, throttled{after: retryAfter(resp)}
	}
	if err := classify(resp.StatusCode); err != nil {
		return nil, err
	}
	var out struct {
		CertPEM string `json:"cert_pem"`
		CAPEM   string `json:"ca_pem"`
	}
	// BOUNDED BEFORE ANYTHING IS PARSED OR VERIFIED (pass-3 claims 33/48). verifyIssued below decides whether the
	// responder is the control plane — but it cannot run until the body has been read, so an unbounded read is a
	// DoS that lands BEFORE the check that would have refused it. Both authenticated siblings bound theirs
	// (client.go:61,130); these two, on the one route that needs no credential at all, did not.
	if err := json.NewDecoder(io.LimitReader(resp.Body, rekeyResponseLimit)).Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: response body did not decode: %v", ErrRekeyTransient, err)
	}
	// VERIFY BEFORE ANYTHING TOUCHES DISK. Two properties, and both must hold:
	//
	//  1. the issued certificate CHAINS TO THE ANCHOR THIS AGENT ALREADY TRUSTS — so a responder who is not the
	//     control plane cannot hand us an identity at all;
	//  2. it certifies the PENDING KEY we just asked for — otherwise a replayed or substituted certificate over
	//     someone else's key would be promoted into key.pem's place and the pair would not match.
	//
	// The response's own ca_pem is deliberately IGNORED and not returned. It is attacker-controlled input on this
	// path, and there is no version of "trust it a little" that is safe.
	if err := verifyIssued([]byte(out.CertPEM), trustedCAPEM, pendingKeyPEM); err != nil {
		return nil, err
	}
	return []byte(out.CertPEM), nil
}

// ErrIssuedCertUntrusted is the refusal when a re-key response does not verify. Distinct from ErrRekeyRefused
// (which is the control plane saying no) because this one means the RESPONDER IS NOT THE CONTROL PLANE — a
// materially different thing for an operator to read, and the agent must not print "mint a join token" for it.
// rekeyResponseLimit bounds both UNAUTHENTICATED response bodies. A certificate and a CA are a few kilobytes; 64
// KiB is the same ceiling the control plane puts on the request side, so neither direction is the loose one.
const rekeyResponseLimit = 64 << 10

var ErrIssuedCertUntrusted = errors.New("the issued certificate does not chain to this agent's trusted CA")

// signedMessage is the agent's half of the proof-of-possession message: the server nonce followed by the DER of
// the CSR being submitted, concatenated with NO separator and NO length prefix.
//
// IT IS A SECOND IMPLEMENTATION OF apps/api/internal/rekey.SignedMessage, AND IT HAS TO BE. The agent is a
// separate Go module and cannot import the control plane's internal packages — so the API's comment claiming
// "one definition, imported by both sides' tests" was never true of this side (pass-3 #43).
//
// What binds them is a GOLDEN VECTOR asserted in BOTH modules' tests, exactly as D10 did for the key fingerprint:
// expressions of one value that cannot share code, pinned to that value. If either side changes this
// construction — adding the length-prefixing the API's own comment contemplates, say — the golden fails on that
// side, loudly, instead of the fleet silently losing the ability to recover.
func signedMessage(nonce, csrDER []byte) []byte {
	msg := make([]byte, 0, len(nonce)+len(csrDER))
	msg = append(msg, nonce...)
	return append(msg, csrDER...)
}

func verifyIssued(certPEM, trustedCAPEM, pendingKeyPEM []byte) error {
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		return fmt.Errorf("%w: response certificate is not PEM", ErrIssuedCertUntrusted)
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return fmt.Errorf("%w: response certificate does not parse: %v", ErrIssuedCertUntrusted, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trustedCAPEM) {
		return fmt.Errorf("%w: the on-disk CA is not usable as a trust anchor", ErrIssuedCertUntrusted)
	}
	// KeyUsageAny: this agent's certificate is a CLIENT credential, and the point here is provenance — did our CA
	// sign it — not what it is allowed to do. The control plane decides EKUs; re-imposing them here would be a
	// second opinion that can only drift from the issuer's.
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("%w: %v", ErrIssuedCertUntrusted, err)
	}
	pending, err := parseRSAKey(pendingKeyPEM)
	if err != nil {
		return fmt.Errorf("%w: pending key unusable: %v", ErrIssuedCertUntrusted, err)
	}
	got, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || got.N.Cmp(pending.N) != 0 || got.E != pending.E {
		return fmt.Errorf("%w: the issued certificate does not certify the key this agent asked for",
			ErrIssuedCertUntrusted)
	}
	return nil
}

func rekeyChallenge(ctx context.Context, apiURL string, ident Identifier) ([]byte, error) {
	body, _ := json.Marshal(ident.fields())
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/api/v1/agent/rekey/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		// A transport fault is NOT a refusal: nothing answered, so nothing was decided.
		return nil, fmt.Errorf("%w: %v", ErrRekeyTransient, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, throttled{after: retryAfter(resp)}
	}
	if err := classify(resp.StatusCode); err != nil {
		return nil, err
	}
	var out struct {
		Nonce string `json:"nonce"`
	}
	// Bounded for the same reason as the submit response, and this one is reached even earlier — before any
	// identity has been asserted at all.
	if err := json.NewDecoder(io.LimitReader(resp.Body, rekeyResponseLimit)).Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: nonce response did not decode: %v", ErrRekeyTransient, err)
	}
	return base64.StdEncoding.DecodeString(out.Nonce)
}

func parseRSAKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, errors.New("not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	any, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	k, ok := any.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return k, nil
}

// classify turns a status code into the ONE distinction the agent may act on.
//
// The refusal BODY is uniform by design and says nothing; the STATUS is the only legitimate signal, and treating
// every non-200 as a permanent refusal threw that away. 403 is the control plane deciding. Anything else is the
// control plane not answering — a proxy, a load balancer, a restart, a captive portal — and must never produce the
// "mint a join token" remedy, because acting on it during an outage destroys a working identity.
func classify(status int) error {
	switch {
	case status == http.StatusOK:
		return nil
	case status == http.StatusForbidden:
		return ErrRekeyRefused
	default:
		return fmt.Errorf("%w: unexpected status %d", ErrRekeyTransient, status)
	}
}
