package aigateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/ipalloc"
)

const internalCAPurpose = "tunnex-ai-internal-ca"
const internalLeafLifetime = 30 * 24 * time.Hour

// InternalEndpoints manages the internal AI endpoint a gateway serves on a
// private address with TLS (AI-KEYS-1 D4, D8, D9). The control plane re-reads
// the row on every request, so turning it off takes effect at once.
type InternalEndpoints struct {
	w    *Workloads
	keys *StaticKeys
	now  func() time.Time
	kick func(ctx context.Context, node uuid.UUID)
}

func NewInternalEndpoints(w *Workloads, keys *StaticKeys) *InternalEndpoints {
	return &InternalEndpoints{w: w, keys: keys, now: time.Now}
}

// SetKick lets a saved change wake the gateway's watch so it polls at once.
func (e *InternalEndpoints) SetKick(kick func(context.Context, uuid.UUID)) {
	if e != nil {
		e.kick = kick
	}
}

func (e *InternalEndpoints) ready() bool { return e != nil && e.w.ready() }

type internalEndpointRow struct {
	api.AIInternalEndpointConfig
	org, node uuid.UUID
}

const internalEndpointColumns = `id,org_id,node_id,enabled,host(listen_addresses[1]),coalesce(host(listen_addresses[2]),''),port,dns_name,source_cidrs::text[],tls_mode,revision,updated_at`

func scanInternalEndpoint(row pgx.Row) (internalEndpointRow, error) {
	var v internalEndpointRow
	var first, second, mode string
	err := row.Scan(&v.Id, &v.org, &v.node, &v.Enabled, &first, &second, &v.Port, &v.DnsName, &v.SourceCidrs, &mode, &v.Revision, &v.UpdatedAt)
	v.ListenAddresses = []string{first}
	if second != "" {
		v.ListenAddresses = append(v.ListenAddresses, second)
	}
	v.TlsMode = api.AIInternalEndpointTLSMode(mode)
	if v.SourceCidrs == nil {
		v.SourceCidrs = []string{}
	}
	return v, err
}

// InternalEndpointState is the capability a gateway reports for its listener.
type InternalEndpointState struct {
	Version      int      `json:"ai_internal_endpoint_version"`
	Ready        bool     `json:"ai_internal_endpoint_ready"`
	Addresses    []string `json:"ai_internal_endpoint_addresses"`
	Port         int      `json:"ai_internal_endpoint_port"`
	Revision     int64    `json:"ai_internal_endpoint_revision"`
	Error        string   `json:"ai_internal_endpoint_error"`
	CertNotAfter string   `json:"ai_internal_endpoint_cert_not_after"`
	CertSHA256   string   `json:"ai_internal_endpoint_cert_sha256"`
}

var hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

func validInternalDNSName(v string) bool {
	return len(v) >= 1 && len(v) <= 253 && hostnamePattern.MatchString(v) && net.ParseIP(v) == nil
}

func internalEndpointInvalid(message string) error {
	return apierr.BadRequest("invalid_ai_internal_endpoint", message)
}

// validateInternalEndpointInput checks the shape. Address ownership is
// checked against the database separately.
func validateInternalEndpointInput(in api.AIInternalEndpointInput) (api.AIInternalEndpointInput, error) {
	if len(in.ListenAddresses) < 1 || len(in.ListenAddresses) > 2 {
		return in, internalEndpointInvalid("Give the tunnel address, one LAN address, or both")
	}
	seen := map[string]bool{}
	addrs := make([]string, len(in.ListenAddresses))
	for i, raw := range in.ListenAddresses {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || !addr.Is4() || !addr.IsPrivate() || seen[addr.String()] {
			return in, internalEndpointInvalid("Listen addresses must be distinct private IPv4 addresses")
		}
		seen[addr.String()] = true
		addrs[i] = addr.String()
	}
	in.ListenAddresses = addrs
	if in.Port < 1024 || in.Port > 65535 || in.Port == 8083 || in.Port == 8084 {
		return in, internalEndpointInvalid("Port must be 1024 to 65535 and not 8083 or 8084")
	}
	if in.DnsName != nil {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(*in.DnsName)), ".")
		switch {
		case name == "":
			in.DnsName = nil
		case !validInternalDNSName(name):
			return in, internalEndpointInvalid("DNS name must be a valid host name")
		default:
			in.DnsName = &name
		}
	}
	if len(in.SourceCidrs) < 1 || len(in.SourceCidrs) > 32 {
		return in, internalEndpointInvalid("Give 1 to 32 private IPv4 source ranges")
	}
	cidrs, ok := canonicalStaticKeyCIDRs(in.SourceCidrs, "internal")
	if !ok {
		return in, internalEndpointInvalid("Source ranges must be distinct private IPv4 ranges written as network/length, inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16")
	}
	in.SourceCidrs = cidrs
	if in.TlsMode != "tunnex_ca" && in.TlsMode != "custom" {
		return in, internalEndpointInvalid("Certificate mode must be tunnex_ca or custom")
	}
	if in.ExpectedRevision < 0 {
		return in, internalEndpointInvalid("Invalid revision")
	}
	return in, nil
}

// gatewayTunnelAddress is the organization's pool gateway address, the one
// the 8083 listener uses. Every VPN device routes it.
func gatewayTunnelAddress(poolCIDR string) string {
	gateway, err := ipalloc.GatewayCIDR(poolCIDR)
	if err != nil {
		return ""
	}
	prefix, err := netip.ParsePrefix(gateway)
	if err != nil || !prefix.Addr().Is4() {
		return ""
	}
	return prefix.Addr().String()
}

func internalEndpointCapability(caps []byte) InternalEndpointState {
	var v InternalEndpointState
	if json.Unmarshal(caps, &v) != nil {
		return InternalEndpointState{}
	}
	return v
}

func (e *InternalEndpoints) Put(ctx context.Context, org, actor, node uuid.UUID, in api.AIInternalEndpointInput) (api.AIInternalEndpoint, error) {
	if !e.ready() {
		return api.AIInternalEndpoint{}, aiUnavailable()
	}
	if org == uuid.Nil || actor == uuid.Nil || node == uuid.Nil {
		return api.AIInternalEndpoint{}, policyInvalid()
	}
	in, err := validateInternalEndpointInput(in)
	if err != nil {
		return api.AIInternalEndpoint{}, err
	}
	tx, err := e.w.policies.pool.Begin(ctx)
	if err != nil {
		return api.AIInternalEndpoint{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	var pool string
	var site *uuid.UUID
	var caps []byte
	var fresh bool
	err = tx.QueryRow(ctx, `SELECT o.pool_cidr,n.site_id,n.capabilities,coalesce(n.policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp(),false)
 FROM nodes n JOIN organizations o ON o.id=n.org_id WHERE n.org_id=$1 AND n.id=$2 AND n.status='active' AND n.revoked_at IS NULL AND o.deleted_at IS NULL FOR SHARE OF n`, org, node).Scan(&pool, &site, &caps, &fresh)
	if errors.Is(err, pgx.ErrNoRows) {
		return api.AIInternalEndpoint{}, apierr.NotFound("not_found", "Gateway not found")
	}
	if err != nil {
		return api.AIInternalEndpoint{}, aiUnavailable()
	}
	if !fresh || internalEndpointCapability(caps).Version < 1 {
		return api.AIInternalEndpoint{}, apierr.Conflict("ai_internal_endpoint_unsupported", "Upgrade this gateway to use the internal AI endpoint, and wait for a current report from it")
	}
	tunnel := gatewayTunnelAddress(pool)
	tunnels, lans := 0, 0
	for _, addr := range in.ListenAddresses {
		if tunnel != "" && addr == tunnel {
			tunnels++
			continue
		}
		approved := false
		if site != nil {
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM site_subnets ss JOIN sites s ON s.id=ss.site_id WHERE s.id=$1 AND s.org_id=$2 AND ss.status='approved' AND $3::inet <<= ss.cidr)`, *site, org, addr).Scan(&approved); err != nil {
				return api.AIInternalEndpoint{}, aiUnavailable()
			}
		}
		if !approved {
			return api.AIInternalEndpoint{}, apierr.Conflict("ai_internal_endpoint_address_unapproved", "Each address must be the gateway's tunnel address or inside an approved subnet of its site")
		}
		lans++
	}
	if tunnels > 1 || lans > 1 {
		return api.AIInternalEndpoint{}, apierr.Conflict("ai_internal_endpoint_address_unapproved", "Use at most the tunnel address and one LAN address")
	}
	current, err := scanInternalEndpoint(tx.QueryRow(ctx, `SELECT `+internalEndpointColumns+` FROM ai_internal_endpoints WHERE org_id=$1 AND node_id=$2 FOR UPDATE`, org, node))
	exists := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return api.AIInternalEndpoint{}, aiUnavailable()
	}
	if exists && current.Revision != in.ExpectedRevision || !exists && in.ExpectedRevision != 0 {
		return api.AIInternalEndpoint{}, policyConflict()
	}
	var row internalEndpointRow
	if exists {
		row, err = scanInternalEndpoint(tx.QueryRow(ctx, `UPDATE ai_internal_endpoints SET enabled=$3,listen_addresses=$4::inet[],port=$5,dns_name=$6,source_cidrs=$7::cidr[],tls_mode=$8,revision=revision+1,updated_by=$9 WHERE org_id=$1 AND node_id=$2 RETURNING `+internalEndpointColumns,
			org, node, in.Enabled, in.ListenAddresses, in.Port, in.DnsName, in.SourceCidrs, string(in.TlsMode), actor))
	} else {
		id, _ := uuid.NewV7()
		row, err = scanInternalEndpoint(tx.QueryRow(ctx, `INSERT INTO ai_internal_endpoints(id,org_id,node_id,enabled,listen_addresses,port,dns_name,source_cidrs,tls_mode,created_by,updated_by) VALUES($1,$2,$3,$4,$5::inet[],$6,$7,$8::cidr[],$9,$10,$10) RETURNING `+internalEndpointColumns,
			id, org, node, in.Enabled, in.ListenAddresses, in.Port, in.DnsName, in.SourceCidrs, string(in.TlsMode), actor))
	}
	if err != nil {
		return api.AIInternalEndpoint{}, aiUnavailable()
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,'ai_gateway.internal_endpoint_changed','node',$3,jsonb_build_object('enabled',$4::boolean,'listen_addresses',$5::text[],'port',$6::int,'cidr_count',$7::int,'tls_mode',$8::text,'revision',$9::bigint))`,
		org, actor, node.String(), row.Enabled, row.ListenAddresses, row.Port, len(row.SourceCidrs), string(row.TlsMode), row.Revision); err != nil {
		return api.AIInternalEndpoint{}, aiUnavailable()
	}
	if tx.Commit(ctx) != nil {
		return api.AIInternalEndpoint{}, aiUnavailable()
	}
	if e.kick != nil {
		e.kick(ctx, node)
	}
	items, err := e.List(ctx, org)
	if err != nil {
		return api.AIInternalEndpoint{}, err
	}
	for _, item := range items {
		if item.NodeId == node {
			return item, nil
		}
	}
	return api.AIInternalEndpoint{}, aiUnavailable()
}

func (e *InternalEndpoints) Delete(ctx context.Context, org, actor, node uuid.UUID) error {
	if !e.ready() {
		return aiUnavailable()
	}
	tx, err := e.w.policies.pool.Begin(ctx)
	if err != nil {
		return aiUnavailable()
	}
	defer rollbackAI(tx)
	res, err := tx.Exec(ctx, `DELETE FROM ai_internal_endpoints WHERE org_id=$1 AND node_id=$2`, org, node)
	if err != nil {
		return aiUnavailable()
	}
	if res.RowsAffected() != 1 {
		return policyNotFound()
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id) VALUES($1,$2,'ai_gateway.internal_endpoint_removed','node',$3)`, org, actor, node.String()); err != nil || tx.Commit(ctx) != nil {
		return aiUnavailable()
	}
	if e.kick != nil {
		e.kick(ctx, node)
	}
	return nil
}

func endpointURL(c api.AIInternalEndpointConfig) string {
	host := c.ListenAddresses[0]
	if c.DnsName != nil && *c.DnsName != "" {
		host = *c.DnsName
	}
	return "https://" + net.JoinHostPort(host, strconv.Itoa(c.Port)) + "/v1"
}

// List returns one row per active gateway of the organization with its
// configuration (if any), capability and status.
func (e *InternalEndpoints) List(ctx context.Context, org uuid.UUID) ([]api.AIInternalEndpoint, error) {
	if !e.ready() {
		return nil, aiUnavailable()
	}
	tx, err := e.w.policies.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, aiUnavailable()
	}
	defer rollbackAI(tx)
	var pool string
	if err = tx.QueryRow(ctx, `SELECT pool_cidr FROM organizations WHERE id=$1 AND deleted_at IS NULL`, org).Scan(&pool); err != nil {
		return nil, workloadLookupError(err, policyNotFound())
	}
	tunnel := gatewayTunnelAddress(pool)
	rows, err := tx.Query(ctx, `SELECT id,name,site_id IS NOT NULL,capabilities,coalesce(policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp(),false)
 FROM nodes WHERE org_id=$1 AND status='active' AND revoked_at IS NULL ORDER BY name,id LIMIT 257`, org)
	if err != nil {
		return nil, aiUnavailable()
	}
	out := []api.AIInternalEndpoint{}
	states := map[uuid.UUID]InternalEndpointState{}
	for rows.Next() {
		var item api.AIInternalEndpoint
		var site, fresh bool
		var caps []byte
		if rows.Scan(&item.NodeId, &item.NodeName, &site, &caps, &fresh) != nil {
			rows.Close()
			return nil, aiUnavailable()
		}
		state := InternalEndpointState{}
		if fresh {
			state = internalEndpointCapability(caps)
		}
		states[item.NodeId] = state
		item.HasSite = &site
		item.Supported = fresh && state.Version >= 1
		if tunnel != "" {
			t := tunnel
			item.TunnelAddress = &t
		}
		out = append(out, item)
	}
	rows.Close()
	if rows.Err() != nil || len(out) > 256 {
		return nil, aiUnavailable()
	}
	endpoints := map[uuid.UUID]internalEndpointRow{}
	erows, err := tx.Query(ctx, `SELECT `+internalEndpointColumns+` FROM ai_internal_endpoints WHERE org_id=$1`, org)
	if err != nil {
		return nil, aiUnavailable()
	}
	for erows.Next() {
		v, scanErr := scanInternalEndpoint(erows)
		if scanErr != nil {
			erows.Close()
			return nil, aiUnavailable()
		}
		endpoints[v.node] = v
	}
	erows.Close()
	if erows.Err() != nil {
		return nil, aiUnavailable()
	}
	for i := range out {
		row, ok := endpoints[out[i].NodeId]
		if !ok {
			continue
		}
		cfg := row.AIInternalEndpointConfig
		out[i].Endpoint = &cfg
		url := endpointURL(cfg)
		out[i].Url = &url
		state := states[out[i].NodeId]
		out[i].Ready = cfg.Enabled && out[i].Supported && state.Ready && state.Revision == cfg.Revision && state.Port == cfg.Port && sameStrings(state.Addresses, cfg.ListenAddresses)
		if state.Error != "" {
			msg := boundedText(state.Error, 256)
			out[i].Error = &msg
		}
		if t, perr := time.Parse(time.RFC3339, state.CertNotAfter); perr == nil {
			out[i].CertificateNotAfter = &t
		}
		if _, herr := hex.DecodeString(state.CertSHA256); herr == nil && len(state.CertSHA256) == 64 {
			v := state.CertSHA256
			out[i].CertificateSha256 = &v
		}
	}
	return out, nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func boundedText(v string, n int) string {
	v = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, v)
	if len(v) > n {
		v = v[:n]
	}
	return v
}

// InternalDesiredState is the gateway's listener document (D9).
type InternalDesiredState struct {
	Version  int                      `json:"version"`
	Endpoint *InternalDesiredEndpoint `json:"endpoint"`
}
type InternalDesiredEndpoint struct {
	ID              uuid.UUID `json:"id"`
	Revision        int64     `json:"revision"`
	ListenAddresses []string  `json:"listen_addresses"`
	Port            int       `json:"port"`
	DNSName         string    `json:"dns_name"`
	SourceCIDRs     []string  `json:"source_cidrs"`
	TLSMode         string    `json:"tls_mode"`
}

// DesiredState returns the calling gateway's document. A disabled or absent
// endpoint is null: the gateway closes its listener.
func (e *InternalEndpoints) DesiredState(ctx context.Context, org, node uuid.UUID) (InternalDesiredState, error) {
	out := InternalDesiredState{Version: 1}
	if !e.ready() {
		return out, aiUnavailable()
	}
	row, err := scanInternalEndpoint(e.w.policies.pool.QueryRow(ctx, `SELECT `+internalEndpointColumns+` FROM ai_internal_endpoints WHERE org_id=$1 AND node_id=$2 AND enabled`, org, node))
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, aiUnavailable()
	}
	d := &InternalDesiredEndpoint{ID: row.Id, Revision: row.Revision, ListenAddresses: row.ListenAddresses, Port: row.Port, SourceCIDRs: row.SourceCidrs, TLSMode: string(row.TlsMode)}
	if row.DnsName != nil {
		d.DNSName = *row.DnsName
	}
	out.Endpoint = d
	return out, nil
}

// EnabledEndpoint returns the gateway's enabled endpoint id and source ranges
// for the mTLS inference route.
func (e *InternalEndpoints) EnabledEndpoint(ctx context.Context, org, node uuid.UUID) (uuid.UUID, []string, error) {
	if !e.ready() {
		return uuid.Nil, nil, aiUnavailable()
	}
	var id uuid.UUID
	var cidrs []string
	err := e.w.policies.pool.QueryRow(ctx, `SELECT id,source_cidrs::text[] FROM ai_internal_endpoints WHERE org_id=$1 AND node_id=$2 AND enabled`, org, node).Scan(&id, &cidrs)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil, policyDenied()
	}
	if err != nil {
		return uuid.Nil, nil, aiUnavailable()
	}
	return id, cidrs, nil
}

// Keys exposes the static key service for the mTLS route.
func (e *InternalEndpoints) Keys() *StaticKeys {
	if e == nil {
		return nil
	}
	return e.keys
}

type internalCA struct {
	cert    *x509.Certificate
	certPEM string
	key     *ecdsa.PrivateKey
}

// CA returns the organization's internal AI CA, creating it on first use.
func (e *InternalEndpoints) CA(ctx context.Context, org uuid.UUID) (api.AIInternalEndpointCA, error) {
	ca, err := e.loadCA(ctx, org, true)
	if err != nil {
		return api.AIInternalEndpointCA{}, err
	}
	sum := sha256.Sum256(ca.cert.Raw)
	return api.AIInternalEndpointCA{CertificatePem: ca.certPEM, NotAfter: ca.cert.NotAfter, Sha256: hex.EncodeToString(sum[:])}, nil
}

// The CA key is sealed with the master key and bound to its organization.
func caAAD(org uuid.UUID) []byte { return []byte(internalCAPurpose + ":" + org.String()) }

func (e *InternalEndpoints) loadCA(ctx context.Context, org uuid.UUID, create bool) (internalCA, error) {
	if !e.ready() || org == uuid.Nil {
		return internalCA{}, aiUnavailable()
	}
	var certPEM, sealed string
	err := e.w.policies.pool.QueryRow(ctx, `SELECT certificate_pem,sealed_key FROM ai_internal_cas WHERE org_id=$1`, org).Scan(&certPEM, &sealed)
	if errors.Is(err, pgx.ErrNoRows) && create {
		newPEM, newSealed, notAfter, cerr := e.newCA(org)
		if cerr != nil {
			return internalCA{}, aiUnavailable()
		}
		if _, err = e.w.policies.pool.Exec(ctx, `INSERT INTO ai_internal_cas(org_id,certificate_pem,sealed_key,not_after) SELECT $1,$2,$3,$4 FROM organizations WHERE id=$1 AND deleted_at IS NULL ON CONFLICT (org_id) DO NOTHING`, org, newPEM, newSealed, notAfter); err != nil {
			return internalCA{}, aiUnavailable()
		}
		// Another request may have won the race; always use the stored CA.
		err = e.w.policies.pool.QueryRow(ctx, `SELECT certificate_pem,sealed_key FROM ai_internal_cas WHERE org_id=$1`, org).Scan(&certPEM, &sealed)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return internalCA{}, policyNotFound()
	}
	if err != nil {
		return internalCA{}, aiUnavailable()
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return internalCA{}, aiUnavailable()
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA {
		return internalCA{}, aiUnavailable()
	}
	der, err := e.w.policies.sealer.OpenWithAAD(sealed, caAAD(org))
	if err != nil {
		return internalCA{}, aiUnavailable()
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil || !key.PublicKey.Equal(cert.PublicKey) {
		return internalCA{}, aiUnavailable()
	}
	return internalCA{cert: cert, certPEM: certPEM, key: key}, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func (e *InternalEndpoints) newCA(org uuid.UUID) (string, string, time.Time, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", time.Time{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return "", "", time.Time{}, err
	}
	now := e.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Tunnex internal AI CA", Organization: []string{"Tunnex organization " + org.String()}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", time.Time{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", time.Time{}, err
	}
	sealed, err := e.w.policies.sealer.SealWithAAD(keyDER, caAAD(org))
	if err != nil {
		return "", "", time.Time{}, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), sealed, tmpl.NotAfter, nil
}

// InternalCertificate is a signed leaf for the calling gateway.
type InternalCertificate struct {
	CertificatePEM string    `json:"certificate_pem"`
	ChainPEM       string    `json:"chain_pem"`
	NotAfter       time.Time `json:"not_after"`
}

// SignCSR signs a 30-day leaf for the calling gateway's own enabled endpoint.
// Only the public key is taken from the CSR: the SANs are the configured
// addresses and DNS name, never the CSR's (D8). serverAuth only, not a CA.
func (e *InternalEndpoints) SignCSR(ctx context.Context, org, node uuid.UUID, csrPEM string) (InternalCertificate, error) {
	if !e.ready() {
		return InternalCertificate{}, aiUnavailable()
	}
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || strings.TrimSpace(string(rest)) != "" {
		return InternalCertificate{}, internalEndpointInvalid("Invalid certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return InternalCertificate{}, internalEndpointInvalid("Invalid certificate request")
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return InternalCertificate{}, internalEndpointInvalid("Unsupported key")
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return InternalCertificate{}, internalEndpointInvalid("Unsupported key")
		}
	default:
		return InternalCertificate{}, internalEndpointInvalid("Unsupported key")
	}
	row, err := scanInternalEndpoint(e.w.policies.pool.QueryRow(ctx, `SELECT `+internalEndpointColumns+` FROM ai_internal_endpoints WHERE org_id=$1 AND node_id=$2 AND enabled`, org, node))
	if errors.Is(err, pgx.ErrNoRows) {
		return InternalCertificate{}, apierr.Conflict("ai_internal_endpoint_disabled", "No enabled internal AI endpoint for this gateway")
	}
	if err != nil {
		return InternalCertificate{}, aiUnavailable()
	}
	if row.TlsMode != "tunnex_ca" {
		return InternalCertificate{}, apierr.Conflict("ai_internal_endpoint_custom_tls", "This endpoint uses the operator's certificate files")
	}
	ca, err := e.loadCA(ctx, org, true)
	if err != nil {
		return InternalCertificate{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return InternalCertificate{}, aiUnavailable()
	}
	now := e.now()
	notAfter := now.Add(internalLeafLifetime)
	if notAfter.After(ca.cert.NotAfter) {
		notAfter = ca.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		Subject:               pkix.Name{CommonName: row.ListenAddresses[0]},
	}
	if _, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	for _, v := range row.ListenAddresses {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(v).To4())
	}
	if row.DnsName != nil && *row.DnsName != "" {
		tmpl.DNSNames = []string{*row.DnsName}
		tmpl.Subject.CommonName = *row.DnsName
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return InternalCertificate{}, aiUnavailable()
	}
	if _, err = e.w.policies.pool.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata) VALUES($1,'ai-internal-endpoint','ai_gateway.internal_endpoint_certificate_issued','node',$2,jsonb_build_object('revision',$3::bigint,'not_after',$4::timestamptz))`, org, node.String(), row.Revision, notAfter); err != nil {
		return InternalCertificate{}, aiUnavailable()
	}
	return InternalCertificate{CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), ChainPEM: ca.certPEM, NotAfter: notAfter}, nil
}
