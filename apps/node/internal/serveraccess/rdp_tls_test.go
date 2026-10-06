package serveraccess

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestRDPCertificatePin(t *testing.T) {
	cert := []byte("independently verified certificate")
	sum := sha256.Sum256(cert)
	cfg := pinnedRDPTLSConfig("SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]))
	if err := cfg.VerifyPeerCertificate([][]byte{cert}, nil); err != nil {
		t.Fatal(err)
	}
	for _, certs := range [][][]byte{nil, {[]byte("different certificate")}} {
		if err := cfg.VerifyPeerCertificate(certs, nil); err == nil {
			t.Fatal("accepted missing or mismatched certificate")
		}
	}
}

// Exercise the TLS handshake itself: a custom callback unit test alone cannot
// prove that TLS actually invokes mandatory pin verification.
func TestRDPCertificatePinHandshake(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	pin := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	for _, tc := range []struct {
		name, fingerprint string
		wantOK            bool
	}{
		{"matching self-signed certificate", pin, true},
		{"changed certificate", "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), false},
		{"missing pin", "", false},
		{"malformed pin", "SHA256:invalid", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			deadline := time.Now().Add(3 * time.Second)
			clientConn.SetDeadline(deadline)
			serverConn.SetDeadline(deadline)
			server := tls.Server(serverConn, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
			done := make(chan error, 1)
			go func() { done <- server.Handshake() }()
			client := tls.Client(clientConn, pinnedRDPTLSConfig(tc.fingerprint))
			err := client.Handshake()
			clientConn.Close()
			serverErr := <-done
			if tc.wantOK {
				if err != nil || serverErr != nil {
					t.Fatalf("matching pin handshake failed: client=%v server=%v", err, serverErr)
				}
			} else if !errors.Is(err, errHostKeyMismatch) {
				t.Fatalf("expected pin rejection, got %v", err)
			}
		})
	}
}
