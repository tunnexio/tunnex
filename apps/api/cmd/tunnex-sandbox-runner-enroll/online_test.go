package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

func signedBundle(t *testing.T, identity localIdentity) bootstrapBundle {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic machine enrollment fixture"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(identity.CSR)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://tunnex.example/sandbox-runner/fixture")
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, csr.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	return bootstrapBundle{EnrollmentID: identity.EnrollmentID, ProfileID: "00000000-0000-4000-8000-000000000003", BindingSHA256: strings.Repeat("a", 64), Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), RunnerCA: ca, APICA: ca, Install: json.RawMessage(`{"version":1}`)}
}

func TestMachineKeysGeneratedLocallyCSRHasNoRequestedAuthority(t *testing.T) {
	identity, err := freshIdentity("https://api.example.invalid", uuid.NewString())
	if err != nil || validateIdentity(identity, identity.Server, identity.EnrollmentID) != nil {
		t.Fatal("local identity invalid")
	}
	block, _ := pem.Decode(identity.CSR)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || len(csr.Extensions) != 0 || csr.Subject.String() != "" {
		t.Fatal("CSR requested authority")
	}
	probe, err := ssh.ParsePrivateKey(identity.ProbeKey)
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(identity.TLSKey)
	private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(private.(ed25519.PrivateKey).Public())
	if err != nil || bytes.Equal(public.Marshal(), probe.PublicKey().Marshal()) {
		t.Fatal("probe must be separate from TLS identity")
	}
	if strings.Contains(string(identity.CSR), "PRIVATE KEY") || strings.Contains(identity.ProbePublicKey, "PRIVATE KEY") {
		t.Fatal("public request contains private identity")
	}
}

func TestPrivateIdentityRetryStableAndWrongBindingRefused(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "private")
	id := uuid.NewString()
	root, first, err := loadIdentity(destination, "https://api.example.invalid", id)
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	root, second, err := loadIdentity(destination, first.Server, first.EnrollmentID)
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	if !bytes.Equal(first.CSR, second.CSR) || !bytes.Equal(first.TLSKey, second.TLSKey) || !bytes.Equal(first.ProbeKey, second.ProbeKey) {
		t.Fatal("retry changed identity")
	}
	if root, _, err := loadIdentity(destination, first.Server, uuid.NewString()); err == nil {
		root.Close()
		t.Fatal("different enrollment adopted private identity")
	}
	if root, _, err := loadIdentity(destination, "https://other.example.invalid", id); err == nil {
		root.Close()
		t.Fatal("different API adopted private identity")
	}
	info, _ := os.Stat(filepath.Join(destination, "identity.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("private identity permissions")
	}
}

func TestPrivateIdentityPartialSymlinkAndMutableDirectoriesRefused(t *testing.T) {
	for _, variant := range []string{"mutable", "partial", "symlink", "private-link"} {
		t.Run(variant, func(t *testing.T) {
			parent := t.TempDir()
			destination := filepath.Join(parent, "private")
			if err := os.Mkdir(destination, 0700); err != nil {
				t.Fatal(err)
			}
			switch variant {
			case "mutable":
				os.Chmod(destination, 0755)
			case "partial":
				os.WriteFile(filepath.Join(destination, "unrelated"), []byte("public fixture"), 0600)
			case "symlink":
				os.Rename(destination, destination+"-other")
				os.Symlink(destination+"-other", destination)
			case "private-link":
				os.WriteFile(filepath.Join(parent, "foreign"), []byte(`{}`), 0600)
				os.Symlink(filepath.Join(parent, "foreign"), filepath.Join(destination, "identity.json"))
			}
			if root, _, err := loadIdentity(destination, "https://api.example.invalid", uuid.NewString()); err == nil {
				root.Close()
				t.Fatal("unsafe identity adopted")
			}
		})
	}
}

func TestReturnedCertificateBoundToLocalKeyAndOriginalEnrollment(t *testing.T) {
	identity, _ := freshIdentity("https://api.example.invalid", uuid.NewString())
	bundle := signedBundle(t, identity)
	if verifyBundle(bundle, identity, time.Now()) != nil {
		t.Fatal("signed fixture refused")
	}
	other, _ := freshIdentity(identity.Server, identity.EnrollmentID)
	if verifyBundle(bundle, other, time.Now()) == nil {
		t.Fatal("foreign private key accepted")
	}
	for _, mutate := range []func(*bootstrapBundle){
		func(b *bootstrapBundle) { b.EnrollmentID = uuid.NewString() },
		func(b *bootstrapBundle) { b.RunnerCA = "invalid public CA" },
		func(b *bootstrapBundle) { b.APICA = "invalid public CA" },
		func(b *bootstrapBundle) { b.Install = json.RawMessage(`null`) },
	} {
		copy := bundle
		mutate(&copy)
		if verifyBundle(copy, identity, time.Now()) == nil {
			t.Fatal("invalid public response accepted")
		}
	}
	if verifyBundle(bundle, identity, time.Now().Add(25*time.Hour)) == nil {
		t.Fatal("expired certificate accepted")
	}
}

func TestBootstrapHTTPSUsesOnlyBoundedPostBodyAndNoPrivateMaterial(t *testing.T) {
	identity, _ := freshIdentity("https://api.example.invalid", uuid.NewString())
	bundle := signedBundle(t, identity)
	token := strings.Repeat("synthetic-bootstrap-", 3)
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.String() != "/api/v1/sandbox-runners/bootstrap" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != "" {
			t.Error("wrong bootstrap boundary")
		}
		raw, _ := io.ReadAll(r.Body)
		var request bootstrapRequest
		if decodeStrict(raw, &request) != nil || request.BootstrapToken != token || request.EnrollmentID != identity.EnrollmentID || request.CertificateRequest != string(identity.CSR) || request.ProbePublicKey != identity.ProbePublicKey || bytes.Contains(raw, []byte("PRIVATE KEY")) {
			t.Error("wrong or secret-bearing public identity")
		}
		json.NewEncoder(w).Encode(bundle)
	}))
	defer server.Close()
	client := server.Client()
	client.Transport.(*http.Transport).TLSClientConfig.MinVersion = tls.VersionTLS13
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for range 2 {
		got, err := exchangeBootstrap(context.Background(), client, server.URL, token, identity)
		if err != nil || got.Certificate != bundle.Certificate {
			t.Fatal("exact certificate retry failed")
		}
	}
	if calls != 2 {
		t.Fatal("unexpected bootstrap count")
	}
}

func TestBootstrapRedirectNeverForwardsToken(t *testing.T) {
	identity, _ := freshIdentity("https://api.example.invalid", uuid.NewString())
	forwarded := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded = true }))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if _, err := exchangeBootstrap(context.Background(), client, server.URL, strings.Repeat("synthetic", 8), identity); err == nil || forwarded {
		t.Fatal("redirect leaked bootstrap token")
	}
}

func TestBootstrapErrorsDoNotEchoResponseOrToken(t *testing.T) {
	identity, _ := freshIdentity("https://api.example.invalid", uuid.NewString())
	secret := strings.Repeat("synthetic-secret-", 4)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403); io.WriteString(w, secret) }))
	defer server.Close()
	_, err := exchangeBootstrap(context.Background(), server.Client(), server.URL, secret, identity)
	if err == nil || strings.Contains(err.Error(), secret) || err != errBootstrap {
		t.Fatal("bootstrap error leaks detail")
	}
}

func TestBootstrapInvalidPublicOriginsAndTokenInputsRefusedBeforeNetwork(t *testing.T) {
	for _, server := range []string{"http://api.example.invalid", "https://user:pass@api.example.invalid", "https://api.example.invalid/path", "https://api.example.invalid?token=x", "https://api.example.invalid/#fragment"} {
		if _, err := apiOrigin(server); err == nil {
			t.Fatal("unsafe API origin")
		}
	}
	for _, token := range []string{"short", strings.Repeat("x", 4097), strings.Repeat("x", 40) + " extra", strings.Repeat("x", 40) + "\nsecond"} {
		err := onlineEnrollment("https://api.example.invalid", uuid.NewString(), filepath.Join(t.TempDir(), "private"), strings.NewReader(token))
		if err != errBootstrap {
			t.Fatal("invalid token not refused before network")
		}
	}
}

func TestMachineBootstrapEndToEndPrivateFilesAndExactRecovery(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "private")
	id := uuid.NewString()
	secret := strings.Repeat("synthetic-bootstrap-", 3)
	var issued bootstrapBundle
	var original bootstrapRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var request bootstrapRequest
		if decodeStrict(raw, &request) != nil || request.EnrollmentID != id || request.BootstrapToken != secret || bytes.Contains(raw, []byte("PRIVATE KEY")) {
			t.Error("invalid bootstrap request")
			w.WriteHeader(400)
			return
		}
		if issued.Certificate == "" {
			original = request
			issued = signedBundle(t, localIdentity{EnrollmentID: id, CSR: []byte(request.CertificateRequest)})
		} else if request.CertificateRequest != original.CertificateRequest || request.ProbePublicKey != original.ProbePublicKey {
			t.Error("retry changed enrolled public identity")
			w.WriteHeader(409)
			return
		}
		json.NewEncoder(w).Encode(issued)
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for range 2 {
		if err := onlineEnrollmentWithClient(server.URL, id, destination, strings.NewReader(secret+"\n"), client); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"identity.json", "runner-key.pem", "probe-key", "runner-cert.pem", "runner-ca.pem", "api-ca.pem", "enrollment.json"} {
		info, err := os.Lstat(filepath.Join(destination, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("machine output not private regular file")
		}
		raw, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil || bytes.Contains(raw, []byte(secret)) {
			t.Fatal("bootstrap token persisted")
		}
		if name == "enrollment.json" && bytes.Contains(raw, []byte("PRIVATE KEY")) {
			t.Fatal("public install response persisted private key")
		}
	}
	private, _ := os.ReadFile(filepath.Join(destination, "runner-key.pem"))
	cert, _ := os.ReadFile(filepath.Join(destination, "runner-cert.pem"))
	if _, err := tls.X509KeyPair(cert, private); err != nil {
		t.Fatal("installed leaf does not match local private key")
	}
	if err := verifyIssuedIdentity(server.URL, id, destination); err != nil {
		t.Fatal("original issued identity failed exact retry verification")
	}
	if err := os.WriteFile(filepath.Join(destination, "runner-cert.pem"), []byte("changed fixture certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if verifyIssuedIdentity(server.URL, id, destination) == nil {
		t.Fatal("changed retained identity accepted without new bootstrap")
	}
}
