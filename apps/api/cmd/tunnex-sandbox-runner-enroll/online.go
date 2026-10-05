package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

const enrollmentLimit = 256 << 10

var (
	errIdentity   = errors.New("machine_identity_refused: retain the private enrollment directory and inspect ownership or partial files")
	errBootstrap  = errors.New("bootstrap_refused: enrollment is expired, canceled, revoked, or its machine identity changed")
	errConnection = errors.New("bootstrap_unavailable: check the HTTPS API connection and retry the same enrollment directory before expiry")
)

type localIdentity struct {
	EnrollmentID   string `json:"enrollment_id"`
	Server         string `json:"server"`
	TLSKey         []byte `json:"tls_key"`
	CSR            []byte `json:"certificate_request"`
	ProbeKey       []byte `json:"probe_key"`
	ProbePublicKey string `json:"probe_public_key"`
}

type bootstrapRequest struct {
	EnrollmentID       string `json:"enrollment_id"`
	BootstrapToken     string `json:"bootstrap_token"`
	CertificateRequest string `json:"certificate_request"`
	ProbePublicKey     string `json:"probe_public_key"`
}

type bootstrapBundle struct {
	EnrollmentID  string          `json:"enrollment_id"`
	ProfileID     string          `json:"profile_id"`
	BindingSHA256 string          `json:"binding_sha256"`
	Certificate   string          `json:"certificate"`
	RunnerCA      string          `json:"runner_ca"`
	APICA         string          `json:"api_ca"`
	Install       json.RawMessage `json:"install"`
}

func apiOrigin(server string) (string, error) {
	u, err := url.Parse(server)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(server, "\x00\n\r") {
		return "", errIdentity
	}
	return "https://" + u.Host, nil
}

func decodeStrict(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return errIdentity
	}
	return nil
}

func freshIdentity(server, enrollment string) (localIdentity, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return localIdentity{}, errIdentity
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return localIdentity{}, errIdentity
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return localIdentity{}, errIdentity
	}
	_, probe, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return localIdentity{}, errIdentity
	}
	block, err := ssh.MarshalPrivateKey(probe, "Tunnex dedicated machine readiness probe")
	if err != nil {
		return localIdentity{}, errIdentity
	}
	public, err := ssh.NewPublicKey(probe.Public())
	if err != nil {
		return localIdentity{}, errIdentity
	}
	return localIdentity{EnrollmentID: enrollment, Server: server, TLSKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), CSR: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), ProbeKey: pem.EncodeToMemory(block), ProbePublicKey: string(ssh.MarshalAuthorizedKey(public))}, nil
}

func validateIdentity(identity localIdentity, server, enrollment string) error {
	if identity.Server != server || identity.EnrollmentID != enrollment {
		return errIdentity
	}
	block, rest := pem.Decode(identity.TLSKey)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return errIdentity
	}
	private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := private.(ed25519.PrivateKey)
	if err != nil || !ok {
		return errIdentity
	}
	block, rest = pem.Decode(identity.CSR)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return errIdentity
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || len(csr.Extensions) != 0 || len(csr.DNSNames) != 0 || len(csr.URIs) != 0 || len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 {
		return errIdentity
	}
	a, _ := x509.MarshalPKIXPublicKey(key.Public())
	b, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if !bytes.Equal(a, b) {
		return errIdentity
	}
	probe, err := ssh.ParsePrivateKey(identity.ProbeKey)
	if err != nil || probe.PublicKey().Type() != "ssh-ed25519" || identity.ProbePublicKey != string(ssh.MarshalAuthorizedKey(probe.PublicKey())) {
		return errIdentity
	}
	return nil
}

func privateRead(root *os.Root, name string) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || !ownedHere(info) || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > enrollmentLimit {
		return nil, errIdentity
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, errIdentity
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errIdentity
	}
	raw, err := io.ReadAll(io.LimitReader(f, enrollmentLimit+1))
	if err != nil || len(raw) > enrollmentLimit {
		return nil, errIdentity
	}
	return raw, nil
}

func ownedHere(info os.FileInfo) bool {
	metadata, ok := info.Sys().(*syscall.Stat_t)
	return ok && metadata.Uid == uint32(os.Geteuid())
}

func privateWrite(root *os.Root, name string, raw []byte) error {
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errIdentity
	}
	_, writeErr := f.Write(raw)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return errIdentity
	}
	return nil
}

func loadIdentity(destination, server, enrollment string) (*os.Root, localIdentity, error) {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination || destination == "/" {
		return nil, localIdentity{}, errIdentity
	}
	if err := os.Mkdir(destination, 0700); err != nil && !os.IsExist(err) {
		return nil, localIdentity{}, errIdentity
	}
	info, err := os.Lstat(destination)
	if err != nil || !info.IsDir() || !ownedHere(info) || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return nil, localIdentity{}, errIdentity
	}
	root, err := os.OpenRoot(destination)
	if err != nil {
		return nil, localIdentity{}, errIdentity
	}
	raw, err := privateRead(root, "identity.json")
	var identity localIdentity
	if err == nil {
		if decodeStrict(raw, &identity) != nil || validateIdentity(identity, server, enrollment) != nil {
			root.Close()
			return nil, localIdentity{}, errIdentity
		}
	} else {
		if _, err := root.Lstat("identity.json"); !os.IsNotExist(err) {
			root.Close()
			return nil, localIdentity{}, errIdentity
		}
		entries, err := os.ReadDir(destination)
		if err != nil || len(entries) != 0 {
			root.Close()
			return nil, localIdentity{}, errIdentity
		}
		identity, err = freshIdentity(server, enrollment)
		if err != nil {
			root.Close()
			return nil, localIdentity{}, errIdentity
		}
		raw, err = json.Marshal(identity)
		if err != nil || privateWrite(root, "identity.json", raw) != nil {
			root.Close()
			return nil, localIdentity{}, errIdentity
		}
	}
	return root, identity, nil
}

func verifyBundle(bundle bootstrapBundle, identity localIdentity, now time.Time) error {
	if bundle.EnrollmentID != identity.EnrollmentID || len(bytes.TrimSpace(bundle.Install)) == 0 || bytes.TrimSpace(bundle.Install)[0] != '{' || !json.Valid(bundle.Install) {
		return errBootstrap
	}
	profile, err := uuid.Parse(bundle.ProfileID)
	if err != nil || profile == uuid.Nil || profile.String() != bundle.ProfileID || !lowerHash(bundle.BindingSHA256, 64) {
		return errBootstrap
	}
	certificate, err := tls.X509KeyPair([]byte(bundle.Certificate), identity.TLSKey)
	if err != nil || len(certificate.Certificate) != 1 {
		return errBootstrap
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.IsCA || len(leaf.URIs) != 1 || leaf.URIs[0].Scheme != "spiffe" || leaf.URIs[0].Host == "" || leaf.URIs[0].RawQuery != "" || leaf.URIs[0].Fragment != "" || leaf.URIs[0].User != nil || leaf.URIs[0].Path == "" || len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || leaf.NotAfter.After(now.Add(25*time.Hour)) {
		return errBootstrap
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(bundle.RunnerCA)) {
		return errBootstrap
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return errBootstrap
	}
	apiRoots := x509.NewCertPool()
	if !apiRoots.AppendCertsFromPEM([]byte(bundle.APICA)) {
		return errBootstrap
	}
	return nil
}

func exchangeBootstrap(ctx context.Context, client *http.Client, server, token string, identity localIdentity) (bootstrapBundle, error) {
	raw, err := json.Marshal(bootstrapRequest{identity.EnrollmentID, token, string(identity.CSR), identity.ProbePublicKey})
	if err != nil {
		return bootstrapBundle{}, errBootstrap
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/api/v1/sandbox-runners/bootstrap", bytes.NewReader(raw))
	if err != nil {
		return bootstrapBundle{}, errBootstrap
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return bootstrapBundle{}, errConnection
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == 401 || response.StatusCode == 403 || response.StatusCode == 404 || response.StatusCode == 409 || response.StatusCode == 410 {
			return bootstrapBundle{}, errBootstrap
		}
		return bootstrapBundle{}, errConnection
	}
	raw, err = io.ReadAll(io.LimitReader(response.Body, enrollmentLimit+1))
	var bundle bootstrapBundle
	if err != nil || len(raw) > enrollmentLimit || decodeStrict(raw, &bundle) != nil || verifyBundle(bundle, identity, time.Now()) != nil {
		return bootstrapBundle{}, errBootstrap
	}
	return bundle, nil
}

func onlineEnrollment(server, enrollment, destination string, input io.Reader) error {
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}, MaxResponseHeaderBytes: 8192}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return onlineEnrollmentWithClient(server, enrollment, destination, input, client)
}

func onlineEnrollmentWithClient(server, enrollment, destination string, input io.Reader, client *http.Client) error {
	server, err := apiOrigin(server)
	parsed, parseErr := uuid.Parse(enrollment)
	if err != nil || parseErr != nil || parsed == uuid.Nil || parsed.String() != enrollment {
		return errIdentity
	}
	token, err := io.ReadAll(io.LimitReader(input, 4097))
	secret := strings.TrimSuffix(string(token), "\n")
	if err != nil || len(token) > 4096 || len(secret) < 32 || strings.ContainsAny(secret, " \t\r\n\x00") {
		return errBootstrap
	}
	root, identity, err := loadIdentity(destination, server, enrollment)
	if err != nil {
		return err
	}
	defer root.Close()
	bundle, err := exchangeBootstrap(context.Background(), client, server, secret, identity)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		return errIdentity
	}
	outputs := map[string][]byte{"runner-key.pem": identity.TLSKey, "probe-key": identity.ProbeKey, "runner-cert.pem": []byte(bundle.Certificate), "runner-ca.pem": []byte(bundle.RunnerCA), "api-ca.pem": []byte(bundle.APICA), "enrollment.json": raw}
	for name, content := range outputs {
		if existing, err := privateRead(root, name); err == nil {
			if sha256.Sum256(existing) != sha256.Sum256(content) {
				return errIdentity
			}
		} else if _, err := root.Lstat(name); !os.IsNotExist(err) || privateWrite(root, name, content) != nil {
			return errIdentity
		}
	}
	return nil
}

func verifyIssuedIdentity(server, enrollment, destination string) error {
	server, err := apiOrigin(server)
	id, parseErr := uuid.Parse(enrollment)
	if err != nil || parseErr != nil || id == uuid.Nil || id.String() != enrollment {
		return errIdentity
	}
	root, identity, err := loadIdentity(destination, server, enrollment)
	if err != nil {
		return errIdentity
	}
	defer root.Close()
	raw, err := privateRead(root, "enrollment.json")
	var bundle bootstrapBundle
	if err != nil || decodeStrict(raw, &bundle) != nil || verifyBundle(bundle, identity, time.Now()) != nil {
		return errBootstrap
	}
	for name, expected := range map[string][]byte{"runner-key.pem": identity.TLSKey, "probe-key": identity.ProbeKey, "runner-cert.pem": []byte(bundle.Certificate), "runner-ca.pem": []byte(bundle.RunnerCA), "api-ca.pem": []byte(bundle.APICA)} {
		actual, err := privateRead(root, name)
		if err != nil || !bytes.Equal(actual, expected) {
			return errIdentity
		}
	}
	return nil
}
