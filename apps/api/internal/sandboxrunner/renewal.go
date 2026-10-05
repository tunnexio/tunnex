package sandboxrunner

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"sync"
	"time"
)

// Issuer is scoped to one controller/runner pair. Its CA key stays on CP. It
// cannot mint other identities, privileges, lease extensions or gateway grants.
type Issuer struct {
	mu         sync.Mutex
	root       *x509.Certificate
	key        crypto.Signer
	controller tls.Certificate
	runnerURI  string
	renewed    []byte
	renewedAt  time.Time
	renewedKey []byte
}

func NewIssuer(caPEM, keyPEM []byte, controller tls.Certificate, runnerURI string) (*Issuer, error) {
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return nil, ErrInvalid
	}
	root, e := x509.ParseCertificate(block.Bytes)
	if e != nil || !root.IsCA {
		return nil, ErrInvalid
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, ErrInvalid
	}
	raw, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, ErrInvalid
	}
	key, ok := raw.(crypto.Signer)
	if !ok {
		return nil, ErrInvalid
	}
	a, _ := x509.MarshalPKIXPublicKey(root.PublicKey)
	b, _ := x509.MarshalPKIXPublicKey(key.Public())
	if string(a) != string(b) {
		return nil, ErrInvalid
	}
	if len(controller.Certificate) == 0 {
		return nil, ErrInvalid
	}
	leaf, e := x509.ParseCertificate(controller.Certificate[0])
	if e != nil || leaf.CheckSignatureFrom(root) != nil || len(leaf.URIs) != 1 || len(leaf.DNSNames) != 1 || leaf.URIs[0].String() == runnerURI {
		return nil, ErrInvalid
	}
	if _, e = NewBroker(runnerURI); e != nil {
		return nil, e
	}
	controller.Leaf = leaf
	return &Issuer{root: root, key: key, controller: controller, runnerURI: runnerURI}, nil
}
func (i *Issuer) issue(leaf *x509.Certificate, usage x509.ExtKeyUsage, now time.Time) ([]byte, error) {
	if now.Before(i.root.NotBefore) || !now.Add(24*time.Hour).Before(i.root.NotAfter) {
		return nil, ErrUnavailable
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, e
	}
	template := &x509.Certificate{SerialNumber: serial, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), URIs: leaf.URIs, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	if usage == x509.ExtKeyUsageServerAuth {
		template.DNSNames = leaf.DNSNames
	}
	der, e := x509.CreateCertificate(rand.Reader, template, i.root, leaf.PublicKey, i.key)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
func (i *Issuer) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if time.Until(i.controller.Leaf.NotAfter) < 12*time.Hour {
		raw, e := i.issue(i.controller.Leaf, x509.ExtKeyUsageServerAuth, time.Now())
		if e != nil {
			return nil, e
		}
		block, _ := pem.Decode(raw)
		leaf, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return nil, e
		}
		i.controller.Certificate = [][]byte{block.Bytes}
		i.controller.Leaf = leaf
	}
	snapshot := i.controller
	return &snapshot, nil
}
func (i *Issuer) RenewRunner(leaf *x509.Certificate) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := time.Now()
	if leaf == nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != i.runnerURI || leaf.CheckSignatureFrom(i.root) != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, ErrInvalid
	}
	if len(i.renewed) > 0 && bytes.Equal(i.renewedKey, leaf.RawSubjectPublicKeyInfo) && now.Sub(i.renewedAt) < time.Hour {
		return append([]byte(nil), i.renewed...), nil
	}
	raw, e := i.issue(leaf, x509.ExtKeyUsageClientAuth, now)
	if e != nil {
		return nil, e
	}
	i.renewed = raw
	i.renewedAt = now
	i.renewedKey = append([]byte(nil), leaf.RawSubjectPublicKeyInfo...)
	return append([]byte(nil), raw...), nil
}
