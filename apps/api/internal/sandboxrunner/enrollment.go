package sandboxrunner

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"time"
)

// Enrollment is an offline operator artifact, never returned by a browser API.
// Private keys must be installed only at their endpoint with mode0600. The CA
// key is installed only on CP for bounded authenticated renewal.
type Enrollment struct{ CA, ControllerCAKey, ControllerCertificate, ControllerKey, RunnerCertificate, RunnerKey []byte }

func Enroll(controllerDNS, controllerURI, runnerURI string, now time.Time) (Enrollment, error) {
	if controllerDNS == "" || controllerURI == runnerURI {
		return Enrollment{}, ErrInvalid
	}
	if _, e := NewBroker(controllerURI); e != nil {
		return Enrollment{}, e
	}
	if _, e := NewBroker(runnerURI); e != nil {
		return Enrollment{}, e
	}
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return Enrollment{}, e
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Tunnex single runner control"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, root, root, key.Public(), key)
	if e != nil {
		return Enrollment{}, e
	}
	root, e = x509.ParseCertificate(der)
	if e != nil {
		return Enrollment{}, e
	}
	caKeyDER, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return Enrollment{}, e
	}
	out := Enrollment{ControllerCAKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER}), CA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	issue := func(identity string, serial int64, usage x509.ExtKeyUsage) ([]byte, []byte, error) {
		_, leafKey, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, nil, e
		}
		uri, _ := url.Parse(identity)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: root.NotBefore, NotAfter: now.Add(24 * time.Hour), URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if usage == x509.ExtKeyUsageServerAuth {
			leaf.DNSNames = []string{controllerDNS}
		}
		der, e := x509.CreateCertificate(rand.Reader, leaf, root, leafKey.Public(), key)
		if e != nil {
			return nil, nil, e
		}
		pk, e := x509.MarshalPKCS8PrivateKey(leafKey)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), e
	}
	out.ControllerCertificate, out.ControllerKey, e = issue(controllerURI, 2, x509.ExtKeyUsageServerAuth)
	if e != nil {
		return Enrollment{}, e
	}
	out.RunnerCertificate, out.RunnerKey, e = issue(runnerURI, 3, x509.ExtKeyUsageClientAuth)
	return out, e
}
