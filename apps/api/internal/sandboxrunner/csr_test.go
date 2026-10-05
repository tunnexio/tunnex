package sandboxrunner

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/url"
	"testing"
	"time"
)

func csrIssuer(t *testing.T) *Issuer {
	t.Helper()
	e, err := Enroll("localhost", "spiffe://tunnex/controller/csr", "spiffe://tunnex/runner/csr", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(e.ControllerCertificate, e.ControllerKey)
	if err != nil {
		t.Fatal(err)
	}
	i, err := NewIssuer(e.CA, e.ControllerCAKey, cert, "spiffe://tunnex/runner/csr")
	if err != nil {
		t.Fatal(err)
	}
	return i
}
func machineCSR(t *testing.T, template *x509.CertificateRequest) []byte {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})
}
func TestCSRSignsOnlyConfiguredIdentityAndKeepsMachineKey(t *testing.T) {
	i := csrIssuer(t)
	raw := machineCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted requested subject"}})
	block, _ := pem.Decode(raw)
	csr, _ := x509.ParseCertificateRequest(block.Bytes)
	cert, err := i.SignRunnerCSR(raw)
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(cert)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != i.runnerURI || leaf.Subject.CommonName != "" || !bytes.Equal(csr.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || time.Until(leaf.NotAfter) > 24*time.Hour+time.Second {
		t.Fatal("CSR broadened configured identity/key/lifetime")
	}
	if bytes.Contains(cert, []byte("PRIVATE KEY")) {
		t.Fatal("signer emitted private key")
	}
}
func TestCSRRejectsIdentityExtensionsMalformedAndForgedRequests(t *testing.T) {
	i := csrIssuer(t)
	u, _ := url.Parse("spiffe://foreign/runner/admin")
	extension := machineCSR(t, &x509.CertificateRequest{URIs: []*url.URL{u}})
	valid := machineCSR(t, &x509.CertificateRequest{})
	block, _ := pem.Decode(valid)
	block.Bytes[len(block.Bytes)-1] ^= 1
	forged := pem.EncodeToMemory(block)
	for _, raw := range [][]byte{nil, []byte("invalid"), append(append([]byte{}, valid...), valid...), extension, forged, make([]byte, 4097)} {
		if _, err := i.SignRunnerCSR(raw); err != ErrInvalid {
			t.Fatal("unsafe CSR accepted", err)
		}
	}
}
func TestCSRReplacementDoesNotReusePreviousKeyRenewal(t *testing.T) {
	i := csrIssuer(t)
	var previous []byte
	for range 2 {
		raw, err := i.SignRunnerCSR(machineCSR(t, &x509.CertificateRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := pem.Decode(raw)
		leaf, _ := x509.ParseCertificate(b.Bytes)
		renewed, err := i.RenewRunner(leaf)
		if err != nil {
			t.Fatal(err)
		}
		b, _ = pem.Decode(renewed)
		next, _ := x509.ParseCertificate(b.Bytes)
		if !bytes.Equal(next.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) || bytes.Equal(next.RawSubjectPublicKeyInfo, previous) {
			t.Fatal("renewal returned previous enrollment key")
		}
		previous = next.RawSubjectPublicKeyInfo
	}
}
