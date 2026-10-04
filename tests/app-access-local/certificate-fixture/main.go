// Nonshipping certificate qualification helper; no production trust overrides.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func writePEM(dir, name, kind string, bytes []byte) error {
	return os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: bytes}), 0600)
}
func issue(dir, name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, until time.Time, client bool) error {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if e != nil {
		return e
	}
	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if client {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "AA8 isolated " + name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, DNSNames: []string{"payroll.apps.example.net", "tunnex-app-proxy"}}
	der, e := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
	if e != nil {
		return e
	}
	private, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		return e
	}
	if e = writePEM(dir, name+".pem", "CERTIFICATE", der); e != nil {
		return e
	}
	return writePEM(dir, name+"-key.pem", "EC PRIVATE KEY", private)
}
func generate(dir string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	if e := os.Chmod(dir, 0700); e != nil {
		return e
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "AA8 isolated certificate qualification CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		return e
	}
	if e = writePEM(dir, "ca.pem", "CERTIFICATE", der); e != nil {
		return e
	}
	private, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		return e
	}
	if e = writePEM(dir, "ca-key.pem", "EC PRIVATE KEY", private); e != nil {
		return e
	}
	for _, item := range []struct {
		name   string
		expiry time.Time
		client bool
	}{{"expired", time.Now().Add(-time.Minute), false}, {"renewed", time.Now().Add(time.Hour), false}, {"gateway", time.Now().Add(time.Hour), false}, {"client-expired", time.Now().Add(-time.Minute), true}, {"client-renewed", time.Now().Add(time.Hour), true}} {
		if e = issue(dir, item.name, ca, key, item.expiry, item.client); e != nil {
			return e
		}
	}
	return os.WriteFile(filepath.Join(dir, "invalid-credential"), []byte("tnxap_child_certificate_qualification_invalid"), 0600)
}
func shortLeaf(dir string) error {
	caBytes, e := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if e != nil {
		return e
	}
	block, _ := pem.Decode(caBytes)
	if block == nil {
		return errors.New("CA")
	}
	ca, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return e
	}
	keyBytes, e := os.ReadFile(filepath.Join(dir, "ca-key.pem"))
	if e != nil {
		return e
	}
	block, _ = pem.Decode(keyBytes)
	if block == nil {
		return errors.New("key")
	}
	key, e := x509.ParseECPrivateKey(block.Bytes)
	if e != nil {
		return e
	}
	return issue(dir, "short", ca, key, time.Now().Add(30*time.Second), false)
}
func expired(err error) bool {
	var invalid x509.CertificateInvalidError
	return errors.As(err, &invalid) && invalid.Reason == x509.Expired
}
func probe(dir, port string, client bool) error {
	bytes, e := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if e != nil {
		return e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bytes) {
		return errors.New("CA")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "payroll.apps.example.net", NextProtos: []string{"http/1.1"}}
	if client {
		config.ServerName = "tunnex-app-proxy"
		// The same callback reads renewed credentials on each handshake; no cached fixture leaf.
		config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c, e := tls.LoadX509KeyPair(filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem"))
			return &c, e
		}
	}
	conn, e := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", "app-proxy:"+port, config)
	if e != nil {
		if expired(e) {
			fmt.Println("certificate_expired_refused")
			return nil
		}
		return errors.New("TLS refused")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, e = fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: payroll.apps.example.net\r\nConnection: close\r\n\r\n")
	if e != nil {
		return errors.New("TLS peer refused")
	}
	buf := make([]byte, 128)
	n, e := conn.Read(buf)
	if e != nil {
		return errors.New("TLS peer refused")
	}
	if n < 12 || string(buf[:12]) != "HTTP/1.1 403" {
		return errors.New("unexpected response")
	}
	fmt.Println("strict_tls_generic_403")
	return nil
}
func main() {
	mode := flag.String("mode", "", "generate|short|public|gateway")
	dir := flag.String("directory", "", "fixture certificate directory")
	flag.Parse()
	var err error
	switch *mode {
	case "generate":
		err = generate(*dir)
	case "short":
		err = shortLeaf(*dir)
	case "public":
		err = probe(*dir, "443", false)
	case "gateway":
		err = probe(*dir, "8444", true)
	default:
		err = errors.New("mode refused")
	}
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"result": "refused", "reason": err.Error()})
		os.Exit(1)
	}
}
