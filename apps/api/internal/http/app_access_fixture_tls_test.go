package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"os"
	"path/filepath"
	"testing"
)

// These files are exclusively leaf credentials in the explicitly mounted owned
// fixture directory. The existing CA private key never leaves its sealed row.
func appAccessFixtureLeaf(t *testing.T, ca *agentca.CA, name, stem string) {
	t.Helper()
	dir := "/owned-aa6-proxy"
	certPath := filepath.Join(dir, stem+"-cert.pem")
	keyPath := filepath.Join(dir, stem+"-key.pem")
	if info, e := os.Lstat(dir); e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("owned fixture certificate mount unavailable")
	}
	certExists, keyExists := false, false
	for i, p := range []string{certPath, keyPath} {
		if info, e := os.Lstat(p); e == nil {
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
				t.Fatal("fixture leaf file ownership mode refused")
			}
			if i == 0 {
				certExists = true
			} else {
				keyExists = true
			}
		} else if !os.IsNotExist(e) {
			t.Fatal("fixture leaf unavailable")
		}
	}
	if certExists != keyExists {
		t.Fatal("partial fixture leaf pair")
	}
	if certExists {
		pair, e := tls.LoadX509KeyPair(certPath, keyPath)
		if e != nil {
			t.Fatal("fixture leaf pair invalid")
		}
		leaf, e := x509.ParseCertificate(pair.Certificate[0])
		if e != nil {
			t.Fatal("fixture leaf invalid")
		}
		if _, e = leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
			t.Fatal("existing fixture leaf does not match owned CA and hostname")
		}
		return
	}
	pair, e := ca.ServerTLSCertificate(name)
	if e != nil {
		t.Fatal("owned fixture leaf issuance failed")
	}
	key, e := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if e != nil {
		t.Fatal("fixture leaf encoding failed")
	}
	cert := []byte{}
	for _, der := range pair.Certificate {
		cert = append(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	write := func(path string, data []byte) {
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal("fixture leaf exclusive write refused")
		}
		if _, e = f.Write(data); e != nil {
			f.Close()
			t.Fatal("fixture leaf write failed")
		}
		if e = f.Close(); e != nil {
			t.Fatal("fixture leaf close failed")
		}
	}
	write(certPath, cert)
	write(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
}
func appAccessFixtureProxyCredential(t *testing.T, ctx context.Context, s *appaccess.Service) {
	t.Helper()
	path := "/owned-aa6-proxy/proxy-credential"
	if info, e := os.Lstat(path); e == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("fixture proxy credential mode refused")
		}
		token, e := os.ReadFile(path)
		if e != nil {
			t.Fatal("fixture proxy credential read failed")
		}
		if _, e = s.AuthenticateProxy(ctx, string(token)); e != nil {
			t.Fatal("retained fixture proxy credential is unavailable")
		}
		return
	} else if !os.IsNotExist(e) {
		t.Fatal("fixture proxy credential unavailable")
	}
	_, token, e := s.IssueProxyCredential(ctx, "owned-aa6-browser-proxy")
	if e != nil {
		t.Fatal("owned fixture proxy credential issuance failed")
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal("fixture proxy credential exclusive write refused")
	}
	if _, e = f.WriteString(token); e != nil {
		f.Close()
		t.Fatal("fixture proxy credential write failed")
	}
	if e = f.Close(); e != nil {
		t.Fatal("fixture proxy credential close failed")
	}
}

func appAccessFixturePublicCA(t *testing.T, ca *agentca.CA) {
	t.Helper()
	path := "/owned-aa6-proxy/ca-cert.pem"
	if info, e := os.Lstat(path); e == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("fixture public CA mode refused")
		}
		raw, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(raw, ca.CertPEM()) {
			t.Fatal("fixture public CA mismatches retained root")
		}
		return
	} else if !os.IsNotExist(e) {
		t.Fatal("fixture public CA read failed")
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal("fixture public CA exclusive write refused")
	}
	if _, e = f.Write(ca.CertPEM()); e != nil {
		f.Close()
		t.Fatal("fixture public CA write failed")
	}
	if e = f.Close(); e != nil {
		t.Fatal("fixture public CA close failed")
	}
}
