// Package ovpn is the OpenVPN control-plane service (S9.1, EPIC 9). Slice 2 provides client-cert
// ISSUANCE: it mints a client profile from the separate OVPN client CA (ovpnca, D-S9.1-1) and
// RECORDS the cert identity (serial, expiry, device binding) so the Slice 5 revocation full-sweep
// and CRL have their source (B2). The client private key is EPHEMERAL (D-S9.2-1) — returned to the
// caller for one-time .ovpn delivery (Slice 4), never persisted.
//
// Edition-independent (D-S9.1-6): the OVPN server + PKI ship open-edition; enforcement is the
// enterprise tier.
package ovpn

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/ovpnca"
)

// sealer seals/opens a secret under the master key (crypto.Sealer) — used for the SERVER private key
// at rest (D-S9.6-CERT-DELIVERY: server keys are stored sealed so they can be re-delivered idempotently,
// distinct from ephemeral client keys).
type sealer interface {
	Seal([]byte) (string, error)
	Open(string) ([]byte, error)
}

// Service issues + records OpenVPN client certificates. The client CA loads LAZILY (D-S9.5-OPTIN(a)):
// it is generated on the FIRST export in an opted-in org, NEVER at boot — so a deployment where no
// org has opted into OpenVPN has no CA row at all (the zero-config golden at the platform tier).
type Service struct {
	q      *sqlc.Queries
	loadCA func(context.Context) (*ovpnca.CA, error)
	sealer sealer
	ca     atomic.Pointer[ovpnca.CA]
}

// NewService wires the OVPN service to the query set + a lazy CA loader (LoadOrCreate, called on
// first use so the CA is generated only when OpenVPN is actually used, honoring D-S9.5-OPTIN(a)) + a
// sealer for the server private key at rest.
func NewService(q *sqlc.Queries, loadCA func(context.Context) (*ovpnca.CA, error), s sealer) *Service {
	return &Service{q: q, loadCA: loadCA, sealer: s}
}

// EnsureServerCert returns the gateway's OpenVPN server material (CA cert + server cert + server key)
// for delivery as desired state (D-S9.6-CERT-DELIVERY). MINT-ONCE: the server cert is minted per
// gateway (IssueServer, server-auth leaf) + recorded with its key SEALED, so every later call
// re-delivers the SAME material (never a fresh mint). The key is returned for the agent to write at
// cfgDir; it crosses the same mTLS control channel as policy/pool (no new trust). Never logged/audited.
func (s *Service) EnsureServerCert(ctx context.Context, orgID, nodeID uuid.UUID, commonName string) (caPEM, certPEM, keyPEM string, err error) {
	ca, err := s.caFor(ctx)
	if err != nil {
		return "", "", "", err
	}
	if row, gerr := s.q.GetOVPNServerCertForNode(ctx, nodeID); gerr == nil {
		key, oerr := s.sealer.Open(row.SealedKey) // re-deliver the recorded material
		if oerr != nil {
			return "", "", "", oerr
		}
		return string(ca.CertPEM()), row.CertPem, string(key), nil
	} else if !errors.Is(gerr, pgx.ErrNoRows) {
		return "", "", "", gerr
	}
	// mint-once.
	p, err := ca.IssueServer(commonName)
	if err != nil {
		return "", "", "", err
	}
	sealed, err := s.sealer.Seal([]byte(p.PrivateKeyPEM))
	if err != nil {
		return "", "", "", err
	}
	if _, err := s.q.InsertOVPNServerCert(ctx, sqlc.InsertOVPNServerCertParams{
		OrgID: orgID, NodeID: nodeID, Serial: p.Serial, CertPem: p.CertPEM, SealedKey: sealed, NotAfter: p.NotAfter,
	}); err != nil {
		return "", "", "", err
	}
	return string(ca.CertPEM()), p.CertPEM, p.PrivateKeyPEM, nil
}

// caFor returns the platform client CA, generating it on first use (lazy — D-S9.5-OPTIN(a)) and
// caching it. A concurrent double-load is harmless: LoadOrCreate is idempotent (the CA row is created
// once; a racing caller reads the same row back).
func (s *Service) caFor(ctx context.Context) (*ovpnca.CA, error) {
	if c := s.ca.Load(); c != nil {
		return c, nil
	}
	c, err := s.loadCA(ctx)
	if err != nil {
		return nil, err
	}
	s.ca.Store(c)
	return c, nil
}

// Issue mints an OVPN client profile for a device and records the cert identity so revocation
// (Slice 5) can build the CRL and the B2 full-sweep can find the serial. The returned Profile
// carries the EPHEMERAL private key (D-S9.2-1): the caller streams it into the .ovpn exactly once
// (Slice 4's one-time ceremony) and discards it — this service persists ONLY the cert identity,
// never the key.
//
// commonName is the cert subject CN — the device's stable identity (set by the caller from the
// device/user binding). Recording happens AFTER a successful signature, so a persisted row always
// corresponds to a real issued cert (the swallowed-audit law's mirror, applied to PKI state).
func (s *Service) Issue(ctx context.Context, orgID, deviceID uuid.UUID, commonName string) (ovpnca.Profile, error) {
	ca, err := s.caFor(ctx)
	if err != nil {
		return ovpnca.Profile{}, err
	}
	p, err := ca.IssueClient(commonName)
	if err != nil {
		return ovpnca.Profile{}, err
	}
	if _, err := s.q.InsertOVPNClientCert(ctx, sqlc.InsertOVPNClientCertParams{
		OrgID:      orgID,
		DeviceID:   deviceID,
		Serial:     p.Serial,
		CommonName: commonName,
		NotAfter:   p.NotAfter,
	}); err != nil {
		return ovpnca.Profile{}, err
	}
	return p, nil
}

// ExportProfile mints a client cert for an already-created OVPN device (the caller runs the
// devices.Service.Create fork first) and assembles the one-time `.ovpn` profile. It returns the
// profile text (carrying the EPHEMERAL private key, delivered ONCE per the S3.4/D2 ceremony) and a
// FINGERPRINT — the cert serial — which is what the caller records in the audit row: never the
// material, only its keyed identity. The device id is the cert CommonName (and the CCD filename,
// Slice 3), so the roster, the cert record, and the compiled /32 all agree on one identity.
//
// host/port are the gateway's OpenVPN remote (resolved by the caller from the device's node). A lost
// profile is NOT re-fetchable — the key is never stored — so recovery is revoke + re-issue (an
// ordinary revoke, Slice 5), never a re-download.
func (s *Service) ExportProfile(ctx context.Context, orgID, actorID, deviceID uuid.UUID, remotes []string, port int) (profile, fingerprint string, err error) {
	ca, err := s.caFor(ctx)
	if err != nil {
		return "", "", err
	}
	p, err := s.Issue(ctx, orgID, deviceID, deviceID.String())
	if err != nil {
		return "", "", err
	}
	// Audit the export with the KEYED FINGERPRINT (the cert serial) — NEVER the material. The audit
	// answers "who exported which client profile, when" without ever recording the key/cert bytes.
	if err := s.audit(ctx, orgID, actorID, "ovpn.profile_exported", deviceID.String(),
		map[string]any{"fingerprint": p.Serial}); err != nil {
		return "", "", err
	}
	profile = BuildProfile(string(ca.CertPEM()), p, remotes, port)
	return profile, p.Serial, nil
}

// RebuildCRL regenerates + stores the org's signed CRL from the FULL current revoked set (D-S9.5-1b:
// rebuilt WHOLE, never appended). This is the ONE shared revocation seam (D-S9.5-1 condition iii): BOTH the
// device-revoke and node-revoke paths call THIS after marking certs revoked — the rebuild lives in one
// place, never re-implemented per caller (the WF-OVPN-10 guard-not-mirrored lesson applied preemptively).
// Per-org, monotonic per-org number. Idempotent. Best-effort at the call site: the device is already
// revoked (roster/ccd-exclusive blocks reconnect); the CRL kills the LIVE session, and the scheduled
// rebuild is the backstop if a single rebuild fails.
func (s *Service) RebuildCRL(ctx context.Context, orgID uuid.UUID) error {
	ca, err := s.caFor(ctx)
	if err != nil {
		return err
	}
	number, err := s.q.BumpOVPNCRLNumber(ctx, orgID) // atomic per-org monotonic allocation
	if err != nil {
		return err
	}
	rows, err := s.q.ListRevokedOVPNSerialsByOrg(ctx, orgID) // the FULL current revoked set
	if err != nil {
		return err
	}
	revoked := make([]ovpnca.RevokedCert, 0, len(rows))
	for _, r := range rows {
		revoked = append(revoked, ovpnca.RevokedCert{Serial: r.Serial, RevokedAt: r.RevokedAt.Time})
	}
	crlPEM, err := ca.GenerateCRL(revoked, number)
	if err != nil {
		return err
	}
	return s.q.SetOVPNCRL(ctx, sqlc.SetOVPNCRLParams{OrgID: orgID, CrlPem: crlPEM, Number: number})
}

// GetCRL returns the org's signed CRL PEM for delivery as desired state. If none exists yet (the org has
// never revoked, or OVPN was just enabled), it lazily generates + stores the EMPTY signed CRL ONCE — so a
// gateway's crl-verify (always-on) never points at a missing file (the WF-OVPN-1 lesson). This is NOT
// recompute-on-fetch: after the first init the row exists and every fetch just READS it (revoke rebuilds it).
func (s *Service) GetCRL(ctx context.Context, orgID uuid.UUID) (string, error) {
	row, err := s.q.GetOVPNCRLForOrg(ctx, orgID)
	if err == nil && len(row.CrlPem) > 0 {
		return string(row.CrlPem), nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	// No CRL (or the placeholder) — generate the empty one once + store.
	if err := s.RebuildCRL(ctx, orgID); err != nil {
		return "", err
	}
	row, err = s.q.GetOVPNCRLForOrg(ctx, orgID)
	if err != nil {
		return "", err
	}
	return string(row.CrlPem), nil
}

func (s *Service) audit(ctx context.Context, orgID, actor uuid.UUID, action, targetID string, meta map[string]any) error {
	b := []byte("{}")
	if meta != nil {
		b, _ = json.Marshal(meta)
	}
	tt := "device"
	_, err := s.q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID:       pgtype.UUID{Bytes: [16]byte(orgID), Valid: true},
		ActorUserID: pgtype.UUID{Bytes: [16]byte(actor), Valid: true},
		Action:      action, TargetType: &tt, TargetID: &targetID, Metadata: b,
	})
	return err
}
