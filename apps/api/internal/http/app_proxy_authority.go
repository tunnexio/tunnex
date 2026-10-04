package http

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/appdomains"
	"github.com/tunnexio/tunnex/packages/apptransport"
)

type appProxyAuthorityPort interface {
	AuthenticateProxy(context.Context, string) (appaccess.AuthenticatedProxy, error)
	LookupRoute(context.Context, appaccess.AuthenticatedProxy, string, bool) (appaccess.Route, error)
	AuthorizeRequest(context.Context, appaccess.AuthenticatedProxy, appaccess.RequestInput, bool) (appaccess.Decision, error)
	RenewLease(context.Context, appaccess.AuthenticatedProxy, appaccess.LeaseInput, bool) (appaccess.Decision, error)
	ChannelAuthorize(context.Context, appaccess.AuthenticatedProxy, appaccess.RouteBinding, string, bool) (time.Time, error)
}

type appProxySessionPort interface {
	RedeemApp(context.Context, appaccess.AuthenticatedProxy, string, string, string, bool) (appaccess.RedeemResult, error)
	RegisterPendingLaunch(context.Context, appaccess.AuthenticatedProxy, appaccess.RouteBinding, string, string, bool) (time.Time, error)
}
type appProxyDomainsPort interface {
	ProxyDomains(context.Context, appaccess.AuthenticatedProxy) (appdomains.Config, error)
}
type appProxyTerminationPort interface {
	StreamTerminated(context.Context, appaccess.AuthenticatedProxy, appaccess.RouteBinding, uuid.UUID, string) error
}
type appProxyTerminatedWire struct {
	Binding  appProxyBindingWire `json:"binding"`
	StreamID uuid.UUID           `json:"stream_id"`
	Reason   string              `json:"reason"`
}
type appProxyRedeemWire struct {
	Code     string `json:"code"`
	Nonce    string `json:"nonce"`
	Hostname string `json:"hostname"`
}
type appProxyRedeemResultWire struct {
	Token     string    `json:"app_session_token"`
	Target    string    `json:"relative_target"`
	ExpiresAt time.Time `json:"expires_at"`
}
type appProxyPendingWire struct {
	Binding   appProxyBindingWire `json:"binding"`
	NonceHash string              `json:"nonce_hash"`
	Target    string              `json:"relative_target"`
}
type appProxyExpiryWire struct {
	ExpiresAt time.Time `json:"expires_at"`
}
type appProxyDecisionWire struct {
	StreamID  uuid.UUID `json:"stream_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type appProxyBindingWire struct {
	OrgID            uuid.UUID `json:"org_id"`
	AppID            uuid.UUID `json:"app_id"`
	GatewayID        uuid.UUID `json:"gateway_id"`
	Generation       uuid.UUID `json:"generation"`
	Revision         int64     `json:"revision"`
	AuthorityVersion int64     `json:"authority_version"`
	Digest           string    `json:"digest"`
	Hostname         string    `json:"hostname"`
	Purpose          string    `json:"purpose"`
}

type appProxyLookupWire struct {
	Hostname string `json:"hostname"`
}
type appProxyMetadataWire struct {
	Method    string `json:"method"`
	Path      string `json:"relative_path"`
	Origin    string `json:"origin"`
	Referer   string `json:"referer"`
	FetchMode string `json:"fetch_mode,omitempty"`
	FetchDest string `json:"fetch_dest,omitempty"`
	FetchUser string `json:"fetch_user,omitempty"`
}
type appProxyAuthorizeWire struct {
	Binding appProxyBindingWire  `json:"binding"`
	Token   string               `json:"app_session_token"`
	Request appProxyMetadataWire `json:"request"`
}
type appProxyLeaseWire struct {
	StreamID uuid.UUID           `json:"stream_id"`
	Binding  appProxyBindingWire `json:"binding"`
}
type appProxyChannelWire struct {
	Binding appProxyBindingWire `json:"binding"`
	Serial  string              `json:"certificate_serial"`
}
type appProxyRouteWire struct {
	Binding   appProxyBindingWire `json:"binding"`
	OriginURL string              `json:"origin_url"`
	Allowed   []string            `json:"allowed_destination_cidrs"`
	CA        string              `json:"origin_ca_pem"`
	CADigest  string              `json:"origin_ca_digest"`
}

func (b appProxyBindingWire) domain() appaccess.RouteBinding {
	return appaccess.RouteBinding{OrgID: b.OrgID, AppID: b.AppID, GatewayID: b.GatewayID, Generation: b.Generation, Revision: b.Revision, AuthorityVersion: b.AuthorityVersion, Digest: b.Digest, Hostname: b.Hostname, Purpose: b.Purpose}
}

var appProxyDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var appProxySerial = regexp.MustCompile(`^[a-f0-9]{1,128}$`)

func (b appProxyBindingWire) valid() bool {
	host, err := apptransport.ExactHost(b.Hostname, "")
	if err != nil || host != b.Hostname {
		return false
	}
	return b.OrgID != uuid.Nil && b.AppID != uuid.Nil && b.GatewayID != uuid.Nil && b.Generation != uuid.Nil && b.Revision > 0 && b.AuthorityVersion > 0 && appProxyDigest.MatchString(b.Digest) && len(b.Hostname) > 0 && len(b.Hostname) <= 253 && b.Purpose == "browser_proxy"
}

// NewAppProxyAuthorityHandler must only be served on its dedicated direct TLS
// listener. Neither browser SessionAuth nor the ordinary agent router mounts it.
func NewAppProxyAuthorityHandler(service appProxyAuthorityPort, entitled func() bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		denyAuth := func() { apierr.Write(w, r, apierr.New(401, "proxy_unauthenticated", "proxy authentication required")) }
		if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || service == nil {
			denyAuth()
			return
		}
		values := r.Header.Values("Authorization")
		if len(values) != 1 || !strings.HasPrefix(values[0], "AppProxy ") {
			denyAuth()
			return
		}
		token := strings.TrimPrefix(values[0], "AppProxy ")
		if len(token) != len(appaccess.ProxyTokenPrefix)+43 || strings.ContainsAny(token, " \t\r\n,") {
			denyAuth()
			return
		}
		principal, err := service.AuthenticateProxy(r.Context(), token)
		if err != nil {
			denyAuth()
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		decisionStart := time.Now()
		paid := entitled != nil && entitled()
		invalid := func() { apierr.Write(w, r, apierr.BadRequest("invalid_request", "invalid proxy authority request")) }
		unavailable := func() {
			apierr.Write(w, r, apierr.Forbidden("browser_authority_unavailable", "application authority unavailable"))
		}
		writeAuthorityError := func(e error) {
			var ae *apierr.Error
			if errors.As(e, &ae) && (ae.Status >= 500 || ae.Status == 401 || ae.Status == 429 || ae.Code == "app_session_invalid") {
				apierr.Write(w, r, e)
			} else {
				unavailable()
			}
		}
		writeDecision := func(d appaccess.Decision, e error) {
			if e != nil {
				writeAuthorityError(e)
				return
			}
			if !d.Allowed || d.StreamID == uuid.Nil || d.LeaseUntil == nil || !d.LeaseUntil.After(time.Now()) || d.LeaseUntil.After(time.Now().Add(4*time.Second)) {
				unavailable()
				return
			}
			until := *d.LeaseUntil
			if limit := decisionStart.Add(4 * time.Second); until.After(limit) {
				until = limit
			}
			if !until.After(time.Now()) {
				unavailable()
				return
			}
			writeJSON(w, appProxyDecisionWire{d.StreamID, until})
		}
		decode := func(v any) bool {
			r.Body = http.MaxBytesReader(w, r.Body, 65536)
			d := json.NewDecoder(r.Body)
			d.DisallowUnknownFields()
			e := d.Decode(v)
			if e == nil {
				var extra any
				e = d.Decode(&extra)
				if e == io.EOF {
					return true
				}
			}
			var bound *http.MaxBytesError
			if errors.As(e, &bound) {
				apierr.Write(w, r, apierr.New(413, "request_body_too_large", "proxy authority request exceeds 64 KiB"))
			} else {
				invalid()
			}
			return false
		}
		switch r.URL.Path {
		case "/internal/app-access/domains":
			svc, ok := service.(appProxyDomainsPort)
			if !ok {
				unavailable()
				return
			}
			var input struct{}
			if !decode(&input) {
				return
			}
			config, err := svc.ProxyDomains(r.Context(), principal)
			if err != nil {
				unavailable()
				return
			}
			writeJSON(w, struct {
				PortalURL     string `json:"portal_url"`
				AppBaseDomain string `json:"app_base_domain"`
			}{config.PortalURL, config.AppBaseDomain})

		case "/internal/app-access/publication-readiness/claim":
			svc, ok := service.(appProxyReadinessPort)
			if !ok {
				unavailable()
				return
			}
			var body appProxyReadinessClaimWire
			if !decode(&body) {
				return
			}
			items, e := svc.ClaimPublicationReadiness(r.Context(), principal, body.InstanceToken, paid)
			if e != nil {
				writeAuthorityError(e)
				return
			}
			if len(items) > 8 {
				unavailable()
				return
			}
			out := appProxyReadinessClaimResultWire{Items: []appProxyReadinessWorkWire{}}
			for _, item := range items {
				out.Items = append(out.Items, appProxyReadinessWorkWire{OperationID: item.OperationID, Version: item.Version, Route: appProxyRoute(item.Route), ReadinessRequestID: item.ReadinessRequestID, Deadline: item.Deadline, ChallengeToken: item.ChallengeToken})
			}
			writeJSON(w, out)
		case "/internal/app-access/publication-readiness/report":
			svc, ok := service.(appProxyReadinessPort)
			if !ok {
				unavailable()
				return
			}
			var body appProxyReadinessReportWire
			if !decode(&body) {
				return
			}
			if !body.Binding.valid() || !appProxySerial.MatchString(body.CertificateSerial) || !appProxyDigest.MatchString(body.ChallengeToken) {
				invalid()
				return
			}
			out, e := svc.ReportPublicationReadiness(r.Context(), principal, appaccess.ReadinessReport{OperationID: body.OperationID, ExpectedOperationVersion: body.ExpectedOperationVersion, Binding: body.Binding.domain(), ReadinessRequestID: body.ReadinessRequestID, InstanceToken: body.InstanceToken, ChallengeToken: body.ChallengeToken, CertificateSerial: body.CertificateSerial, PublicDNSStatus: body.PublicDNSStatus, PublicTLSStatus: body.PublicTLSStatus, DNSStatus: body.DNSStatus, ConnectStatus: body.ConnectStatus, TLSStatus: body.TLSStatus, ErrorCode: body.ErrorCode}, paid)
			if e != nil {
				writeAuthorityError(e)
				return
			}
			writeJSON(w, appProxyReadinessReportResultWire{OperationID: out.ID, Version: out.Version, Status: out.Status})
		case "/internal/app-access/route-lookup":
			var body appProxyLookupWire
			if !decode(&body) {
				return
			}
			if len(body.Hostname) == 0 || len(body.Hostname) > 253 {
				invalid()
				return
			}
			route, e := service.LookupRoute(r.Context(), principal, body.Hostname, paid)
			if e != nil {
				apierr.Write(w, r, apierr.New(404, "route_unavailable", "application route unavailable"))
				return
			}
			// A successful route can only originate from the serving publication store.
			b := route.RouteBinding
			expected, hostErr := apptransport.ExactHost(body.Hostname, "")
			wire := appProxyBindingWire{b.OrgID, b.AppID, b.GatewayID, b.Generation, b.Revision, b.AuthorityVersion, b.Digest, b.Hostname, b.Purpose}
			if hostErr != nil || expected != b.Hostname || !wire.valid() {
				apierr.Write(w, r, apierr.New(404, "route_unavailable", "application route unavailable"))
				return
			}
			writeJSON(w, appProxyRouteWire{appProxyBindingWire{b.OrgID, b.AppID, b.GatewayID, b.Generation, b.Revision, b.AuthorityVersion, b.Digest, b.Hostname, b.Purpose}, route.OriginURL, route.AllowedDestinationCIDRs, route.OriginCAPEM, route.OriginCADigest})
		case "/internal/app-access/authorize":
			var body appProxyAuthorizeWire
			if !decode(&body) {
				return
			}
			if !body.Binding.valid() || len(body.Token) > 256 || len(body.Request.Method) == 0 || len(body.Request.Method) > 32 || len(body.Request.Path) == 0 || len(body.Request.Path) > 8192 || !strings.HasPrefix(body.Request.Path, "/") || strings.HasPrefix(body.Request.Path, "//") || len(body.Request.Origin) > 2048 || len(body.Request.Referer) > 8192 || len(body.Request.FetchMode) > 32 || len(body.Request.FetchDest) > 32 || len(body.Request.FetchUser) > 8 {
				invalid()
				return
			}
			d, e := service.AuthorizeRequest(r.Context(), principal, appaccess.RequestInput{Binding: body.Binding.domain(), SessionToken: body.Token, Method: body.Request.Method, RelativePath: body.Request.Path, Origin: body.Request.Origin, Referer: body.Request.Referer, FetchMode: body.Request.FetchMode, FetchDest: body.Request.FetchDest, FetchUser: body.Request.FetchUser}, paid)
			writeDecision(d, e)
		case "/internal/app-access/leases/renew":
			var body appProxyLeaseWire
			if !decode(&body) {
				return
			}
			if body.StreamID == uuid.Nil || !body.Binding.valid() {
				invalid()
				return
			}
			d, e := service.RenewLease(r.Context(), principal, appaccess.LeaseInput{StreamID: body.StreamID, Binding: body.Binding.domain()}, paid)
			writeDecision(d, e)
		case "/internal/app-access/stream-terminated":
			var body appProxyTerminatedWire
			if !decode(&body) {
				return
			}
			if !body.Binding.valid() || body.StreamID == uuid.Nil || (body.Reason != "connection_closed" && body.Reason != "lease_expired") {
				invalid()
				return
			}
			port, ok := service.(appProxyTerminationPort)
			if !ok {
				apierr.Write(w, r, apierr.New(503, "app_access_unavailable", "application authority unavailable"))
				return
			}
			if err := port.StreamTerminated(r.Context(), principal, body.Binding.domain(), body.StreamID, body.Reason); err != nil {
				apierr.Write(w, r, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/internal/app-access/pending-launch":
			var body appProxyPendingWire
			if !decode(&body) {
				return
			}
			if !body.Binding.valid() || !appProxyDigest.MatchString(body.NonceHash) || len(body.Target) == 0 || len(body.Target) > 8192 {
				invalid()
				return
			}
			port, ok := service.(appProxySessionPort)
			if !ok {
				unavailable()
				return
			}
			until, e := port.RegisterPendingLaunch(r.Context(), principal, body.Binding.domain(), body.NonceHash, body.Target, paid)
			if e != nil {
				writeAuthorityError(e)
				return
			}
			if !until.After(time.Now()) || until.After(time.Now().Add(10*time.Minute)) {
				unavailable()
				return
			}
			if limit := decisionStart.Add(10 * time.Minute); until.After(limit) {
				until = limit
			}
			writeJSON(w, appProxyExpiryWire{until})
		case "/internal/app-access/redeem":
			var body appProxyRedeemWire
			if !decode(&body) {
				return
			}
			if len(body.Code) != 43 || len(body.Nonce) != 43 || len(body.Hostname) == 0 || len(body.Hostname) > 253 {
				invalid()
				return
			}
			port, ok := service.(appProxySessionPort)
			if !ok {
				unavailable()
				return
			}
			out, e := port.RedeemApp(r.Context(), principal, body.Code, body.Nonce, body.Hostname, paid)
			if e != nil {
				writeAuthorityError(e)
				return
			}
			if len(out.AppSessionToken) != 49 || !out.ExpiresAt.After(time.Now()) || len(out.RelativeTarget) == 0 || len(out.RelativeTarget) > 8192 {
				unavailable()
				return
			}
			writeJSON(w, appProxyRedeemResultWire{out.AppSessionToken, out.RelativeTarget, out.ExpiresAt})
		case "/internal/app-access/channel-authorize":
			var body appProxyChannelWire
			if !decode(&body) {
				return
			}
			if !body.Binding.valid() || !appProxySerial.MatchString(body.Serial) {
				invalid()
				return
			}
			until, e := service.ChannelAuthorize(r.Context(), principal, body.Binding.domain(), body.Serial, paid)
			if e != nil {
				writeAuthorityError(e)
				return
			}
			if !until.After(time.Now()) || until.After(time.Now().Add(4*time.Second)) {
				unavailable()
				return
			}
			if limit := decisionStart.Add(4 * time.Second); until.After(limit) {
				until = limit
			}
			if r.Context().Err() != nil || !until.After(time.Now()) {
				unavailable()
				return
			}
			writeJSON(w, appProxyExpiryWire{ExpiresAt: until})
		default:
			http.NotFound(w, r)
		}
	})
}
