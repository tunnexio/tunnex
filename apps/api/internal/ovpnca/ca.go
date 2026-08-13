// Package ovpnca is the OpenVPN CLIENT certificate authority (S9.1, EPIC 9). It is a
// SEPARATE trust root from agentca (D-S9.1-1): an OVPN client certificate must NEVER be
// able to authenticate as a node agent, and vice-versa. The two CAs also have opposite
// lifecycles — the agent CA issues 48h leaves and revokes by refusing renewal (no CRL),
// whereas OVPN client certs are LONG-LIVED (D-S9.2-2) and revoked before expiry via a CRL
// (Slice 5), which is exactly why they cannot share the agent CA's no-CRL model.
//
// This package is EDITION-INDEPENDENT (D-S9.1-6): the OVPN server + PKI ship open-edition;
// only enforcement (the compiler) is enterprise-gated. Storage mirrors agentca.LoadOrCreate
// (sealed under the master key in platform_secrets, fail-loud on unusable, never regenerate).
package ovpnca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// secretName is the platform_secrets key for the OVPN client CA — DISTINCT from agentca's
// "agent_ca" so the two roots are independent (trust isolation, D-S9.1-1).
const secretName = "ovpn_client_ca"

// ClientCertTTL is the lifetime of an issued OpenVPN client certificate (D-S9.2-2). Long-lived
// by design — the opposite of the 48h agent CA. Revocation BEFORE expiry is the CRL (Slice 5),
// NOT refuse-renewal; at expiry the client re-downloads a fresh profile (no in-band renewal).
const ClientCertTTL = 365 * 24 * time.Hour

// ServerCertTTL is the lifetime of an OpenVPN SERVER certificate (S9.1 Slice 4a) — the leaf the
// gateway's openvpn process presents, which clients verify via the CA in their .ovpn (with
// remote-cert-tls server, i.e. the server-auth EKU). Long-lived like the client cert; a gateway
// re-enroll re-issues it.
const ServerCertTTL = 2 * 365 * 24 * time.Hour

type sealer interface {
	Seal([]byte) (string, error)
	Open(string) ([]byte, error)
}

// CA signs OpenVPN client certificates and exposes the pool an OpenVPN server verifies clients
// against.
type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *rsa.PrivateKey
}

// Profile is the material one issuance produces. PrivateKeyPEM is EPHEMERAL (D-S9.2-1): the
// caller streams it into the .ovpn exactly once and NEVER persists it — only Serial/NotAfter
// (the cert identity) are recorded, so the Slice 5 CRL sweep has its source.
type Profile struct {
	CertPEM       string
	PrivateKeyPEM string
	Serial        string
	NotAfter      time.Time
}

// LoadOrCreate loads the OVPN client CA from platform_secrets, generating it on first boot.
// Fails loudly (never regenerates) if the stored CA is present but unusable — regenerating
// would orphan every issued OpenVPN client (their certs would no longer chain).
func LoadOrCreate(ctx context.Context, q *sqlc.Queries, s sealer) (*CA, bool, error) {
	row, err := q.GetPlatformSecret(ctx, secretName)
	if err == nil {
		ca, lerr := load(row, s)
		if lerr != nil {
			return nil, false, fmt.Errorf(
				"OVPN client CA exists but is unusable; refusing to regenerate "+
					"(a new CA would orphan every issued OpenVPN client): %w", lerr)
		}
		return ca, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}

	_, sealedKey, certPEM, err := generate(s)
	if err != nil {
		return nil, false, err
	}
	if err := q.InsertPlatformSecret(ctx, sqlc.InsertPlatformSecretParams{
		Name: secretName, SecretSealed: []byte(sealedKey), PublicPem: ptr(string(certPEM)),
	}); err != nil {
		return nil, false, err
	}
	// Re-read in case a concurrent boot won the insert (ON CONFLICT DO NOTHING).
	row, err = q.GetPlatformSecret(ctx, secretName)
	if err != nil {
		return nil, false, err
	}
	loaded, err := load(row, s)
	if err != nil {
		return nil, false, err
	}
	return loaded, true, nil
}

func generate(s sealer) (*CA, string, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, "", nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          bigSerial(),
		Subject:               pkix.Name{CommonName: "Tunnex OpenVPN Client CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	sealedKey, err := s.Seal(keyPEM)
	if err != nil {
		return nil, "", nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	return &CA{cert: cert, certPEM: certPEM, key: key}, sealedKey, certPEM, nil
}

func load(row sqlc.PlatformSecret, s sealer) (*CA, error) {
	keyPEM, err := s.Open(string(row.SecretSealed))
	if err != nil {
		return nil, fmt.Errorf("decrypt CA key: %w", err)
	}
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, errors.New("malformed CA key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	if row.PublicPem == nil {
		return nil, errors.New("missing CA certificate")
	}
	cblk, _ := pem.Decode([]byte(*row.PublicPem))
	if cblk == nil {
		return nil, errors.New("malformed CA cert PEM")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	return &CA{cert: cert, certPEM: []byte(*row.PublicPem), key: key}, nil
}

// IssueClient generates a client keypair SERVER-SIDE (D-S9.2-1), signs a client-auth leaf valid
// for ClientCertTTL, and returns the profile material. The private key is RETURNED to the caller
// and never retained by this package — the caller delivers it once (the .ovpn one-time ceremony,
// Slice 4) and discards it. The returned Serial is the CRL identity (recorded by the ovpn service).
func (c *CA) IssueClient(commonName string) (Profile, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Profile{}, err
	}
	sn := bigSerial()
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(ClientCertTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return Profile{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return Profile{
		CertPEM:       string(certPEM),
		PrivateKeyPEM: string(keyPEM),
		Serial:        serialString(sn),
		NotAfter:      tmpl.NotAfter,
	}, nil
}

// IssueServer generates the OpenVPN SERVER keypair + a SERVER-AUTH leaf valid for ServerCertTTL
// (S9.1 Slice 4a). The gateway's openvpn process presents this cert; clients verify it with
// `remote-cert-tls server` (the server-auth EKU) against the CA in their .ovpn. The key is returned
// to the caller for placement at the gateway (never persisted here). The server cert is distinct
// from a client cert by EKU: a client cert must NEVER be usable as a server and vice-versa.
func (c *CA) IssueServer(commonName string) (Profile, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Profile{}, err
	}
	sn := bigSerial()
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(ServerCertTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return Profile{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return Profile{
		CertPEM:       string(certPEM),
		PrivateKeyPEM: string(keyPEM),
		Serial:        serialString(sn),
		NotAfter:      tmpl.NotAfter,
	}, nil
}

// CertPEM returns the CA certificate (safe to distribute — it ships inside every .ovpn as the
// <ca> block so the client verifies the server, and the server verifies the client against it).
func (c *CA) CertPEM() []byte { return c.certPEM }

// Pool returns a cert pool trusting this CA (the OpenVPN server verifies clients against it).
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// CRLValidity is the CRL's nextUpdate horizon (Slice 5 / D-S9.5-1 condition a). Generous so a CRL never
// EXPIRES between regenerations: an expired CRL can fail-OPEN on some OpenVPN versions (silently
// un-revoking the fleet), so the service regenerates on every revoke AND on a schedule well inside this
// window — the CRL served is always fresh AND never past nextUpdate.
const CRLValidity = 30 * 24 * time.Hour

// RevokedCert is one CRL entry: the hex cert serial + when it was revoked.
type RevokedCert struct {
	Serial    string
	RevokedAt time.Time
}

// GenerateCRL signs a COMPLETE certificate revocation list from the given revoked set (D-S9.5-1(b):
// rebuilt from the FULL current set, NEVER appended — a CRL is a complete statement; an incremental one
// that drops an entry is a silent un-revocation). An EMPTY set yields a valid, signed, EMPTY CRL
// (D-S9.5-2: crl-verify is always-on with a real/empty CRL, never a missing file — the WF-OVPN-1 lesson).
// number is the monotonic CRL sequence number (the service supplies a strictly-increasing value).
func (c *CA) GenerateCRL(revoked []RevokedCert, number int64) ([]byte, error) {
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, r := range revoked {
		b, err := hex.DecodeString(r.Serial)
		if err != nil {
			return nil, fmt.Errorf("crl: bad serial %q: %w", r.Serial, err)
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   new(big.Int).SetBytes(b),
			RevocationTime: r.RevokedAt.UTC(),
		})
	}
	now := time.Now()
	tmpl := &x509.RevocationList{
		RevokedCertificateEntries: entries,
		Number:                    big.NewInt(number),
		ThisUpdate:                now.Add(-time.Minute),
		NextUpdate:                now.Add(CRLValidity),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, c.cert, c.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}

// Fingerprint is a short, non-reversible id of the CA cert, safe to log.
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	return hex.EncodeToString(sum[:6])
}

// SelfTest issues a throwaway client cert and verifies it chains to this CA with the ClientAuth
// EKU — proving the CA can mint verifiable client profiles at boot.
func (c *CA) SelfTest() error {
	p, err := c.IssueClient("selftest")
	if err != nil {
		return err
	}
	blk, _ := pem.Decode([]byte(p.CertPEM))
	if blk == nil {
		return errors.New("selftest: malformed issued cert")
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     c.Pool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("selftest: issued client cert does not verify: %w", err)
	}
	return nil
}

func bigSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(err) // rand.Reader failure is unrecoverable
	}
	return n
}

func serialString(sn *big.Int) string { return hex.EncodeToString(sn.Bytes()) }

func ptr[T any](v T) *T { return &v }
