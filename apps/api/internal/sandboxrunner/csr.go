package sandboxrunner

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"time"
)

// SignRunnerCSR accepts a machine-generated key, not requested identities. The
// issuer can mint only its configured runner URI; private material stays local.
func (i *Issuer) SignRunnerCSR(raw []byte) ([]byte, error) {
	if len(raw) > 4096 {
		return nil, ErrInvalid
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalid
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.PublicKeyAlgorithm != x509.Ed25519 || len(csr.Extensions) != 0 {
		return nil, ErrInvalid
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
		return nil, ErrInvalid
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	identity, _ := url.Parse(i.runnerURI)
	leaf := &x509.Certificate{PublicKey: csr.PublicKey, URIs: []*url.URL{identity}}
	return i.issue(leaf, x509.ExtKeyUsageClientAuth, time.Now())
}
