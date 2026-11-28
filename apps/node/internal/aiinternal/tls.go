package aiinternal

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
)

// CustomCertDir holds the operator's certificate files for the custom TLS mode (D8). The key file must
// be readable by its owner only; the private key is read on each handshake and never sent anywhere.
const CustomCertDir = "/var/lib/tunnex-node/ai-internal"

const (
	customCertFile = "tls-cert.pem"
	customKeyFile  = "tls-key.pem"
	pemFileLimit   = 64 << 10
	maxChainCerts  = 4
)

// served is a certificate the listener can present, with what the gateway reports about it.
type served struct {
	cert     *tls.Certificate
	leaf     *x509.Certificate
	sha256   string
	notAfter time.Time
}

func newServed(chain [][]byte, key any, leaf *x509.Certificate) *served {
	sum := sha256.Sum256(leaf.Raw)
	return &served{
		cert:     &tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf},
		leaf:     leaf,
		sha256:   hex.EncodeToString(sum[:]),
		notAfter: leaf.NotAfter,
	}
}

// covers reports whether the leaf is valid for every configured address and the DNS name.
func covers(leaf *x509.Certificate, ep *Endpoint) bool {
	for _, addr := range ep.Addresses {
		if leaf.VerifyHostname(addr.String()) != nil {
			return false
		}
	}
	return ep.DNSName == "" || leaf.VerifyHostname(ep.DNSName) == nil
}

// needsIssue is true when the Tunnex-CA leaf must be (re)issued: none yet, it does not cover the current
// addresses and name, it is not valid now, or a third of its lifetime or less is left.
func needsIssue(s *served, ep *Endpoint, now time.Time) bool {
	if s == nil || !covers(s.leaf, ep) || now.Before(s.leaf.NotBefore) || !now.Before(s.leaf.NotAfter) {
		return true
	}
	lifetime := s.leaf.NotAfter.Sub(s.leaf.NotBefore)
	return s.leaf.NotAfter.Sub(now) <= lifetime/3
}

// newCSR makes a fresh ECDSA P-256 key, kept only in memory, and a CSR naming exactly the configured
// addresses (IP SANs) and DNS name (DNS SAN).
func newCSR(ep *Endpoint) (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	tmpl := &x509.CertificateRequest{}
	for _, addr := range ep.Addresses {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.IP(addr.AsSlice()))
	}
	tmpl.Subject = pkix.Name{CommonName: ep.Addresses[0].String()}
	if ep.DNSName != "" {
		tmpl.DNSNames = []string{ep.DNSName}
		tmpl.Subject.CommonName = ep.DNSName
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, "", err
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// parseCertificates reads only CERTIFICATE blocks, between 1 and max of them, with nothing else around.
func parseCertificates(raw string, max int) ([]*x509.Certificate, error) {
	rest := []byte(raw)
	var out []*x509.Certificate
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(out) == max {
			return nil, errors.New("unexpected PEM content")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
		rest = next
	}
	if len(out) == 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("unexpected PEM content")
	}
	return out, nil
}

// verifyIssued accepts the control plane's answer only when the leaf is for our key, covers every
// configured address and name, is valid now for server authentication, and chains to chain_pem.
func verifyIssued(key *ecdsa.PrivateKey, resp control.AIInternalCertificate, ep *Endpoint, now time.Time) (*served, error) {
	leaves, err := parseCertificates(resp.CertificatePEM, 1)
	if err != nil {
		return nil, errors.New("certificate response is invalid")
	}
	leaf := leaves[0]
	chain, err := parseCertificates(resp.ChainPEM, maxChainCerts)
	if err != nil {
		return nil, errors.New("certificate chain is invalid")
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("certificate is not for this key")
	}
	if leaf.IsCA || !covers(leaf, ep) {
		return nil, errors.New("certificate does not cover the endpoint")
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	served := [][]byte{leaf.Raw}
	for _, c := range chain {
		if !c.IsCA {
			return nil, errors.New("certificate chain is invalid")
		}
		if bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil {
			roots.AddCert(c)
			continue
		}
		intermediates.AddCert(c)
		served = append(served, c.Raw)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, errors.New("certificate does not chain to the internal AI CA")
	}
	return newServed(served, key, leaf), nil
}

// readPEMFile reads a bounded regular file. With private set, the file must not be readable or
// writable by group or others (mode 0600 or stricter).
func readPEMFile(path string, private bool) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return nil, errKeyPermissions
	}
	raw, err := io.ReadAll(io.LimitReader(f, pemFileLimit+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > pemFileLimit {
		return nil, errors.New("file too large")
	}
	return raw, nil
}

var errKeyPermissions = errors.New("key file is readable by others")

// loadCustom reads the operator's certificate and key. The pair must match and the leaf must be valid
// now; whether it covers the configured addresses is reported, not enforced.
func loadCustom(dir string, now time.Time) (*served, error) {
	keyPEM, err := readPEMFile(filepath.Join(dir, customKeyFile), true)
	if err != nil {
		return nil, err
	}
	certPEM, err := readPEMFile(filepath.Join(dir, customCertFile), false)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, errors.New("certificate and key do not form a pair")
	}
	leaf := pair.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return nil, err
		}
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("certificate is not valid now")
	}
	return newServed(pair.Certificate, pair.PrivateKey, leaf), nil
}

// sniAllowed implements the endpoint's SNI rule: an empty SNI (a client that connects by address) is
// always allowed; otherwise the SNI must be the configured DNS name.
func sniAllowed(dnsName, sni string) bool {
	if sni == "" {
		return true
	}
	return dnsName != "" && strings.EqualFold(strings.TrimSuffix(sni, "."), dnsName)
}

// tlsConfig serves the current certificate. TLS 1.2 is the minimum and only HTTP/1.1 is offered, as
// on the other relays.
func tlsConfig(dnsName string, current func() (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if !sniAllowed(dnsName, hello.ServerName) {
				return nil, errors.New("unexpected SNI")
			}
			return current()
		},
	}
}
