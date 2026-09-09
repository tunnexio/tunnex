package connectivity

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

var ErrProfile = errors.New("invalid relay profile")
var ErrProfileConflict = errors.New("relay profile changed")

type RelayProfile struct {
	Enabled          bool
	URL              string
	SecretConfigured bool
	Revision         int64
}

type RelayConfig struct {
	Enabled          bool
	URL              string
	Secret           string
	ClearSecret      bool
	ExpectedRevision int64
}

type RelayAccess struct {
	URL       string
	Username  string
	Password  string
	ExpiresAt time.Time
}

// Profile never returns the sealed or plaintext shared secret.
func (s *Store) Profile(ctx context.Context, org uuid.UUID) (RelayProfile, error) {
	row, err := sqlc.New(s.pool).ReadConnectivityProfile(ctx, org)
	if errors.Is(err, pgx.ErrNoRows) {
		return RelayProfile{}, nil
	}
	if err != nil {
		return RelayProfile{}, err
	}
	return publicProfile(row), nil
}

// Configure must only be called after the dedicated admin permission check.
func (s *Store) Configure(ctx context.Context, org uuid.UUID, c RelayConfig) (RelayProfile, error) {
	if org == uuid.Nil || s.sealer == nil || c.ExpectedRevision < 0 || (c.URL != "" && !validRelayURL(c.URL)) || (c.Secret != "" && (len(c.Secret) < 32 || len(c.Secret) > 4096)) || (c.ClearSecret && c.Secret != "") {
		return RelayProfile{}, ErrProfile
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return RelayProfile{}, err
	}
	defer tx.Rollback(ctx)
	q := sqlc.New(tx)
	if err := q.EnsureConnectivityProfile(ctx, org); err != nil {
		return RelayProfile{}, err
	}
	old, err := q.LockConnectivityProfile(ctx, org)
	if err != nil {
		return RelayProfile{}, err
	}
	if old.Revision != c.ExpectedRevision {
		return RelayProfile{}, ErrProfileConflict
	}
	sealed := old.SecretSealed
	if c.ClearSecret {
		sealed = nil
	}
	if c.Secret != "" {
		v, err := s.sealer.Seal([]byte(org.String() + ":" + c.Secret))
		if err != nil {
			return RelayProfile{}, ErrProfile
		}
		sealed = &v
	}
	if c.Enabled && (c.URL == "" || sealed == nil) {
		return RelayProfile{}, ErrProfile
	}
	row, err := q.SaveConnectivityProfile(ctx, sqlc.SaveConnectivityProfileParams{OrgID: org, RelayUrl: c.URL, SecretSealed: sealed, Enabled: c.Enabled, ExpectedRevision: c.ExpectedRevision})
	if errors.Is(err, pgx.ErrNoRows) {
		return RelayProfile{}, ErrProfileConflict
	}
	if err != nil {
		return RelayProfile{}, err
	}
	if err := q.RevokeOrgConnectivitySessions(ctx, org); err != nil {
		return RelayProfile{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RelayProfile{}, err
	}
	return publicProfile(row), nil
}

func publicProfile(row sqlc.ConnectivityProfile) RelayProfile {
	return RelayProfile{row.Enabled, row.RelayUrl, row.SecretSealed != nil, row.Revision}
}

func (s *Store) relayAccess(ctx context.Context, q *sqlc.Queries, m *Mailbox, now time.Time) error {
	row, err := q.ReadConnectivityProfile(ctx, m.Session.Binding.OrgID)
	if err != nil {
		return err
	}
	if row.RelayUrl == "" {
		return nil
	} // inert legacy/internal profile; never enabled by Configure
	if !row.Enabled || row.SecretSealed == nil || s.sealer == nil || !validRelayURL(row.RelayUrl) {
		return ErrDenied
	}
	plain, err := s.sealer.Open(*row.SecretSealed)
	if err != nil {
		return ErrDenied
	}
	prefix := m.Session.Binding.OrgID.String() + ":"
	if !strings.HasPrefix(string(plain), prefix) {
		return ErrDenied
	}
	snap := Snapshot{Current: m.Session.Binding, OptedIn: true, OwnerActiveMember: true, DeviceEligible: true, GatewayEligible: true}
	now, err = s.reserveIssuance(ctx, q, m.Session.Binding, m.principal.Side, now)
	if err != nil {
		return err
	}
	creds, err := m.Session.IssueRelayCredentials(m.principal, snap, now, plain[len(prefix):])
	if err != nil {
		return err
	}
	m.Relay = &RelayAccess{row.RelayUrl, creds.Username, creds.Password, creds.ExpiresAt}
	return nil
}

func validRelayURL(raw string) bool {
	if len(raw) > 512 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "turns" || u.Host != "" || u.User != nil || u.Fragment != "" || u.RawQuery != "transport=tcp" {
		return false
	}
	host, port, err := net.SplitHostPort(u.Opaque)
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Zone() == "" && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}
