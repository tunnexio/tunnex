package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"github.com/tunnexio/tunnex/apps/api/internal/backup"
	"github.com/tunnexio/tunnex/apps/api/internal/config"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/dbconn"
)

const appProxyServerName = "tunnex-app-proxy"

type appProxyCertificateResult struct {
	ServerName string    `json:"server_name"`
	CASHA256   string    `json:"ca_sha256"`
	LeafSHA256 string    `json:"leaf_sha256"`
	Serial     string    `json:"serial"`
	NotAfter   time.Time `json:"not_after"`
}

// This command signs one fixed-purpose server leaf under the already bootstrapped
// enrollment CA. It neither initializes roots of trust nor changes entitlement.
func appProxyCertificate(ctx context.Context, cfg config.Config, args []string, out io.Writer) error {
	return fixedProxyCertificate(ctx, cfg, args, out, "app-proxy-certificate", appProxyServerName)
}

func beamProxyCertificate(ctx context.Context, cfg config.Config, args []string, out io.Writer) error {
	return fixedProxyCertificate(ctx, cfg, args, out, "beam-proxy-certificate", "tunnex-beam-proxy")
}

func fixedProxyCertificate(ctx context.Context, cfg config.Config, args []string, out io.Writer, command, serverName string) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	directory := flags.String("output-dir", "", "new exclusive private directory for the gateway TLS pair and public CA")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected certificate command arguments")
	}
	if err := validateCertificateOutput(*directory); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return backup.WithAppRestoreGuard(cfg.AppAccessRestoreMarker, func() error {
		master, err := existingCertificateMaster(cfg)
		if err != nil {
			return err
		}
		defer clear(master)
		sealer, err := crypto.NewSealer(master)
		if err != nil {
			return errors.New("existing master key is unusable")
		}
		pool, err := dbconn.NewPool(ctx, cfg.DatabaseURL)
		if err != nil {
			return errors.New("certificate authority database unavailable")
		}
		defer pool.Close()
		// A single read-only snapshot makes LoadOrCreate below a load-only operation:
		// an absent CA is rejected explicitly, and SQL writes cannot succeed.
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			return errors.New("certificate authority snapshot unavailable")
		}
		defer tx.Rollback(ctx)
		ceiling, err := supportedSchemaVersion()
		if err != nil {
			return err
		}
		var version uint
		var dirty bool
		if err := tx.QueryRow(ctx, "SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&version, &dirty); err != nil || dirty || version != ceiling {
			return errors.New("certificate issuance requires clean schema equal to this binary ceiling")
		}
		q := sqlc.New(tx)
		authority, err := q.GetAppAccessInstallationAuthority(ctx)
		if err != nil || authority.Generation == uuid.Nil || authority.Version < 1 || !authority.RecoveryCompletedAt.Valid {
			return errors.New("certificate issuance requires completed installation authority")
		}
		if _, err := q.GetPlatformSecret(ctx, "agent_ca"); err != nil {
			return errors.New("existing bootstrapped enrollment CA required; no CA created")
		}
		ca, created, err := agentca.LoadOrCreate(ctx, q, sealer)
		if err != nil || created {
			return errors.New("existing enrollment CA cannot be loaded; no replacement allowed")
		}
		pair, err := ca.ServerTLSCertificate(serverName)
		if err != nil || len(pair.Certificate) < 2 {
			return errors.New("gateway certificate issuance failed")
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return errors.New("gateway certificate invalid")
		}
		chains, err := leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: serverName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		if err != nil {
			return errors.New("gateway certificate does not verify against the existing enrollment CA")
		}
		var certPEM []byte
		for _, der := range pair.Certificate {
			certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
		if err != nil {
			return errors.New("gateway leaf key serialization failed")
		}
		defer clear(keyDER)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		defer clear(keyPEM)
		if err := tx.Commit(ctx); err != nil {
			return errors.New("certificate authority snapshot incomplete")
		}
		if err := writeCertificateOutput(*directory, certPEM, keyPEM, ca.CertPEM()); err != nil {
			return err
		}
		caHash, leafHash := sha256.Sum256(pair.Certificate[1]), sha256.Sum256(pair.Certificate[0])
		notAfter := leaf.NotAfter
		for _, cert := range chains[0] {
			if cert.NotAfter.Before(notAfter) {
				notAfter = cert.NotAfter
			}
		}
		return json.NewEncoder(out).Encode(appProxyCertificateResult{serverName, hex.EncodeToString(caHash[:]), hex.EncodeToString(leafHash[:]), leaf.SerialNumber.Text(16), notAfter})
	})
}

// Match the server's file > inline > volume precedence, but never initialize a
// missing key or load the unrelated session secret.
func existingCertificateMaster(cfg config.Config) ([]byte, error) {
	var raw []byte
	path := cfg.MasterKeyFile
	if path == "" && cfg.MasterKey != "" {
		raw = []byte(cfg.MasterKey)
	} else {
		if path == "" {
			if !filepath.IsAbs(cfg.SecretsDir) {
				return nil, errors.New("existing master key requires the configured absolute secrets directory")
			}
			path = filepath.Join(cfg.SecretsDir, "master.key")
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, errors.New("existing master key required; no key initialized")
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("existing master key file must be regular")
		}
		raw, err = io.ReadAll(io.LimitReader(f, 4097))
		if err != nil || len(raw) > 4096 {
			return nil, errors.New("existing master key cannot be read")
		}
	}
	defer clear(raw)
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != crypto.KeySize {
		clear(key)
		return nil, errors.New("existing master key is malformed")
	}
	return key, nil
}

func validateCertificateOutput(directory string) error {
	if !filepath.IsAbs(directory) || directory != filepath.Clean(directory) {
		return errors.New("certificate output requires a new absolute directory")
	}
	parent := filepath.Dir(directory)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return errors.New("certificate output parent must exist without symlinks")
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("certificate output parent must be private")
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		return errors.New("certificate output already exists or cannot be inspected; refusing overwrite")
	}
	return nil
}

func writeCertificateOutput(directory string, cert, key, ca []byte) error {
	if err := validateCertificateOutput(directory); err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return errors.New("cannot exclusively create certificate output directory")
	}
	// Failure retains the private partial directory for operator inspection. A
	// retry cannot overwrite it or silently replace an already selected key pair.
	for _, file := range []struct {
		name string
		data []byte
	}{{"gateway-cert.pem", cert}, {"gateway-key.pem", key}, {"agent-ca.pem", ca}} {
		f, err := os.OpenFile(filepath.Join(directory, file.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errors.New("certificate output incomplete; inspect retained private directory")
		}
		_, err = f.Write(file.data)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return errors.New("certificate output incomplete; inspect retained private directory")
		}
	}
	for _, path := range []string{directory, filepath.Dir(directory)} {
		f, err := os.Open(path)
		if err != nil {
			return errors.New("certificate output durability unconfirmed; inspect private directory")
		}
		err = f.Sync()
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return errors.New("certificate output durability unconfirmed; inspect private directory")
		}
	}
	return nil
}
