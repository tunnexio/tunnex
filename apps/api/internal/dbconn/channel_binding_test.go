package dbconn_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/tunnexio/tunnex/apps/api/internal/dbconn"
)

// A real verified TLS connection must not make an unbound authentication method
// acceptable. Keep passwords synthetic and the ephemeral TLS private key in memory.
func TestRequiredChannelBindingRejectsAuthenticationDowngrade(t *testing.T) {
	methods := []struct {
		name    string
		message pgproto3.BackendMessage
	}{
		{"trust", &pgproto3.AuthenticationOk{}},
		{"password", &pgproto3.AuthenticationCleartextPassword{}},
		{"md5", &pgproto3.AuthenticationMD5Password{Salt: [4]byte{1, 2, 3, 4}}},
		{"scram_without_plus", &pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}}},
	}
	for _, path := range []string{"direct", "migration_adapter", "runtime_pool"} {
		for _, method := range methods {
			t.Run(path+"/"+method.name, func(t *testing.T) {
				raw, result := rejectingTLSServer(t, method.message)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				var connectErr error
				if path == "runtime_pool" {
					pool, err := dbconn.NewPool(ctx, raw)
					if err != nil {
						t.Fatalf("pool configuration: %v", err)
					}
					connectErr = pool.Ping(ctx)
					pool.Close()
				} else {
					cfg, err := dbconn.ParseConfig(raw)
					if err != nil {
						t.Fatalf("configuration: %v", err)
					}
					if cfg.ChannelBinding != "require" || cfg.RequireAuth != "scram-sha-256" {
						t.Fatal("required channel binding/authentication policy was not preserved")
					}
					if path == "migration_adapter" {
						db := stdlib.OpenDB(*cfg)
						connectErr = db.PingContext(ctx)
						_ = db.Close()
					} else {
						conn, err := pgx.ConnectConfig(ctx, cfg)
						connectErr = err
						if conn != nil {
							_ = conn.Close(ctx)
						}
					}
				}
				if connectErr == nil {
					t.Error("accepted authentication without required channel binding")
				}
				select {
				case err := <-result:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(4 * time.Second):
					t.Fatal("mock authentication exchange did not complete")
				}
			})
		}
	}
}

func rejectingTLSServer(t *testing.T, auth pgproto3.BackendMessage) (string, <-chan error) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "public-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	result := make(chan error, 1)
	go func() {
		result <- func() error {
			conn, err := listener.Accept()
			if err != nil {
				return fmt.Errorf("accept: %w", err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
			var sslRequest [8]byte
			if _, err := io.ReadFull(conn, sslRequest[:]); err != nil {
				return fmt.Errorf("SSL request: %w", err)
			}
			if binary.BigEndian.Uint32(sslRequest[4:]) != 80877103 {
				return fmt.Errorf("expected PostgreSQL SSL request")
			}
			if _, err := conn.Write([]byte{'S'}); err != nil {
				return err
			}
			secure := tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
			if err := secure.Handshake(); err != nil {
				return fmt.Errorf("TLS handshake: %w", err)
			}
			backend := pgproto3.NewBackend(secure, secure)
			if _, err := backend.ReceiveStartupMessage(); err != nil {
				return fmt.Errorf("startup: %w", err)
			}
			backend.Send(auth)
			if _, ok := auth.(*pgproto3.AuthenticationOk); ok {
				backend.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
				backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			}
			if err := backend.Flush(); err != nil {
				return err
			}
			var header [5]byte
			_, err = io.ReadFull(secure, header[:])
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return fmt.Errorf("client did not promptly refuse authentication: %w", err)
			}
			if header[0] == 'p' {
				return fmt.Errorf("client transmitted a password/authentication response despite required channel binding")
			}
			return fmt.Errorf("client sent unexpected message %q instead of refusing authentication", header[0])
		}()
	}()
	u := &url.URL{Scheme: "postgres", User: url.UserPassword("fixture", "synthetic-not-a-credential"), Host: listener.Addr().String(), Path: "/fixture"}
	q := url.Values{"sslmode": {"verify-full"}, "sslrootcert": {caPath}, "channel_binding": {"require"}, "connect_timeout": {"2"}}
	u.RawQuery = q.Encode()
	return u.String(), result
}
