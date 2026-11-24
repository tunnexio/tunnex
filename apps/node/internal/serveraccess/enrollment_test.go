package serveraccess

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/tunnexio/tunnex/packages/apptransport/bootstrap"
	"golang.org/x/crypto/ssh"
)

func TestSetupDestinationAndOutputLimits(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "8.8.8.8", "localhost"} {
		if validateSetupJob(bootstrap.Job{IP: ip, Port: 22, Account: "ubuntu", Script: "reviewed"}) == nil {
			t.Fatal("unsafe target accepted", ip)
		}
	}
	if validateSetupJob(bootstrap.Job{IP: "10.2.3.4", Port: 22, Account: "ubuntu", Script: "reviewed", Fingerprint: "SHA256:x"}) != nil {
		t.Fatal("private target refused")
	}
	if validateSetupJob(bootstrap.Job{IP: "10.2.3.4", Port: 22, Account: "ubuntu", Script: "reviewed", HostKeyAttestation: true}) != nil {
		t.Fatal("attested job without a pin refused")
	}
	// SA-UX-2: without attestation from the control plane, an unpinned job is never run (no trust on first use).
	if validateSetupJob(bootstrap.Job{IP: "10.2.3.4", Port: 22, Account: "ubuntu", Script: "reviewed"}) == nil {
		t.Fatal("unpinned, unattested job accepted")
	}
	b := &boundedSetupOutput{}
	if _, e := b.Write(make([]byte, 65537)); e == nil {
		t.Fatal("unbounded output accepted")
	}
}
func TestSetupOutputRequiresStructuredResult(t *testing.T) {
	if _, e := parseSetupOutput([]byte("no result")); e == nil {
		t.Fatal("missing result accepted")
	}
	result, e := parseSetupOutput([]byte("Detected Linux\nBEGIN TUNNEX SSH RESULT\n{\"version\":1,\"accounts\":[\"ubuntu\"]}\nEND TUNNEX SSH RESULT\n"))
	if e != nil || result.Version != 1 {
		t.Fatal(result, e)
	}
}

func TestSetupHostKeyCallbackPinsOrRecords(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(pub)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	otherKey, _ := ssh.NewPublicKey(other)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecKey, _ := ssh.NewPublicKey(&ec.PublicKey)
	fp := ssh.FingerprintSHA256(key)

	proof := hostKeyProof{}
	if e := setupHostKeyCallback(bootstrap.Job{HostKeyAttestation: true}, &proof)("", nil, key); e != nil || proof.seen != fp {
		t.Fatal("attested job did not record the presented key", e, proof)
	}
	proof = hostKeyProof{}
	if e := setupHostKeyCallback(bootstrap.Job{HostKeyAttestation: true}, &proof)("", nil, ecKey); !errors.Is(e, errHostKeyMismatch) || proof.seen != "" {
		t.Fatal("non-ed25519 host key accepted")
	}
	if e := setupHostKeyCallback(bootstrap.Job{HostKeyAttestation: true, Fingerprint: fp}, &proof)("", nil, otherKey); !errors.Is(e, errHostKeyMismatch) {
		t.Fatal("manual pin not enforced with attestation")
	}
	if e := setupHostKeyCallback(bootstrap.Job{Fingerprint: fp}, &proof)("", nil, key); e != nil {
		t.Fatal("legacy pin refused", e)
	}
	if e := setupHostKeyCallback(bootstrap.Job{}, &proof)("", nil, key); !errors.Is(e, errHostKeyMismatch) {
		t.Fatal("unpinned key accepted without attestation")
	}
}

func TestAttestationLineIsExtractedFromBoundedOutput(t *testing.T) {
	line := bootstrap.AttestationPrefix + `{"v":1}`
	out := []byte(line + "\nDetected Linux\nBEGIN TUNNEX SSH RESULT\n{}\nEND TUNNEX SSH RESULT\n")
	if got := attestationFrom(out); got != line {
		t.Fatalf("got %q", got)
	}
	if attestationFrom([]byte("no attestation")) != "" {
		t.Fatal("phantom attestation")
	}
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'a'
	}
	if attestationFrom(append([]byte(bootstrap.AttestationPrefix), long...)) != "" {
		t.Fatal("oversized attestation accepted")
	}
}
