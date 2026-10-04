package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGeneratedExpiredAndRenewedTrust(t *testing.T) {
	dir := t.TempDir()
	if generate(dir) != nil {
		t.Fatal("fixture generate")
	}
	data, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	block, _ := pem.Decode(data)
	ca, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, name := range []string{"expired", "renewed"} {
		data, _ = os.ReadFile(filepath.Join(dir, name+".pem"))
		block, _ = pem.Decode(data)
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			t.Fatal(e)
		}
		_, e = cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "payroll.apps.example.net", CurrentTime: time.Now()})
		if name == "expired" && !expired(e) {
			t.Fatal("expired chain accepted")
		}
		if name == "renewed" && e != nil {
			t.Fatal("same-CA renewal refused")
		}
	}
	info, _ := os.Stat(filepath.Join(dir, "ca-key.pem"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("private key mode")
	}
}
