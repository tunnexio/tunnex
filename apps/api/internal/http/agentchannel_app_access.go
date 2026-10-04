package http

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/packages/apptransport"
)

type appAccessBroker = apptransport.Broker

type appAccessGatewayPort interface {
	AuthorizeChannel(context.Context, appaccess.AuthenticatedGateway, uuid.UUID, uuid.UUID, int64, string, string, bool) (time.Time, error)
	ReportCapability(context.Context, appaccess.AuthenticatedGateway, int32) (appaccess.GatewayRuntime, error)
	DesiredForGateway(context.Context, appaccess.AuthenticatedGateway, bool) (appaccess.Desired, error)
	CompleteCheck(context.Context, appaccess.AuthenticatedGateway, appaccess.Result, bool) (appaccess.Check, error)
	ReportApplied(context.Context, appaccess.AuthenticatedGateway, appaccess.Applied, bool) (appaccess.GatewayRuntime, error)
}

func (a *AgentChannel) SetAppAccessConnector(service appAccessGatewayPort, manager *licence.Manager) {
	a.appAccess = service
	a.appAccessDispatch = &appAccessDispatchState{active: map[uuid.UUID]context.CancelFunc{}, gateways: map[uuid.UUID]int{}}
	a.appAccessEntitled = func() bool { return licenceOrCommunity(manager).Has(licence.FeatAppAccess, time.Now()) }
	if a.appAccessBroker != nil {
		a.appAccessBroker.Close()
	}
	a.appAccessBroker = apptransport.NewBroker(func(ctx context.Context, b apptransport.Binding, serial string) (time.Time, error) {
		org, e1 := uuid.Parse(b.OrgID)
		gateway, e2 := uuid.Parse(b.GatewayID)
		app, e3 := uuid.Parse(b.AppID)
		generation, e4 := uuid.Parse(b.Generation)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || service == nil {
			return time.Time{}, apierr.Forbidden("invalid_assignment", "invalid app connector assignment")
		}
		return service.AuthorizeChannel(ctx, appaccess.AuthenticatedGateway{OrgID: org, GatewayID: gateway, CertSerial: serial}, app, generation, b.Revision, b.Digest, b.Purpose, a.appAccessHasEntitlement())
	})
}
func appAccessGateway(node sqlc.Node) appaccess.AuthenticatedGateway {
	// This is a purpose-scoped service argument, never a new principal. The node
	// was returned by the one authenticateAgent seam and the service rechecks its
	// exact current serial, active gateway and live organization before work.
	return appaccess.AuthenticatedGateway{OrgID: node.OrgID, GatewayID: node.ID, CertSerial: node.CertSerial}
}
func (a *AgentChannel) appAccessAvailable(w http.ResponseWriter, r *http.Request) bool {
	if a.appAccess == nil {
		apierr.Write(w, r, apierr.New(503, "app_access_unavailable", "App Access connector service is unavailable"))
		return false
	}
	return true
}
func (a *AgentChannel) appAccessHasEntitlement() bool {
	return a.appAccessEntitled != nil && a.appAccessEntitled()
}
func decodeAppAccessAgent(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(target)
	if err == nil {
		var trailing any
		err = decoder.Decode(&trailing)
		if err == io.EOF {
			return true
		}
	}
	var bound *http.MaxBytesError
	if errors.As(err, &bound) {
		apierr.Write(w, r, apierr.New(413, "request_body_too_large", "App Access connector report exceeds 8 KiB"))
	} else {
		apierr.Write(w, r, apierr.BadRequest("invalid_request", "one strict JSON object required"))
	}
	return false
}

type appAccessCapabilityWire struct {
	ProtocolVersion *int32 `json:"protocol_version"`
}

func (a *AgentChannel) appAccessCapability(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok || !a.appAccessAvailable(w, r) {
		return
	}
	var body appAccessCapabilityWire
	if !decodeAppAccessAgent(w, r, &body) {
		return
	}
	if body.ProtocolVersion == nil || *body.ProtocolVersion < 0 || *body.ProtocolVersion > 65535 {
		apierr.Write(w, r, apierr.BadRequest("invalid_capability", "bounded protocol version required"))
		return
	}
	out, err := a.appAccess.ReportCapability(r.Context(), appAccessGateway(node), *body.ProtocolVersion)
	if err != nil {
		apierr.Write(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, appAccessGatewayRuntime(out))
}

// These explicit wire types mirror the shared OpenAPI agent-only schemas. They
// stay off the generated browser router and carry no caller-controlled org/node.
type appAccessAssignmentWire struct {
	Generation              uuid.UUID `json:"generation"`
	OrgID                   uuid.UUID `json:"org_id"`
	GatewayID               uuid.UUID `json:"gateway_id"`
	AppID                   uuid.UUID `json:"app_id"`
	Revision                int64     `json:"revision"`
	Digest                  string    `json:"digest"`
	Purpose                 string    `json:"purpose"`
	OriginURL               string    `json:"origin_url"`
	AllowedDestinationCIDRs []string  `json:"allowed_destination_cidrs"`
	OriginCAPEM             string    `json:"origin_ca_pem"`
	OriginCADigest          string    `json:"origin_ca_digest"`
}

type appAccessDesiredWire struct {
	ProtocolVersion int32                     `json:"protocol_version"`
	Purpose         string                    `json:"purpose"`
	Withdrawn       bool                      `json:"withdrawn"`
	Reason          string                    `json:"reason"`
	Assignments     []appAccessAssignmentWire `json:"assignments"`
	Checks          []api.AppAccessCheck      `json:"checks"`
}

func (a *AgentChannel) appAccessDesired(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok || !a.appAccessAvailable(w, r) {
		return
	}
	out, err := a.appAccess.DesiredForGateway(r.Context(), appAccessGateway(node), a.appAccessHasEntitlement())
	if err != nil {
		apierr.Write(w, r, err)
		return
	}
	assignments := make([]appAccessAssignmentWire, len(out.Assignments))
	for i, row := range out.Assignments {
		assignments[i] = appAccessAssignmentWire{row.Generation, row.OrgID, row.GatewayID, row.AppID, row.Revision, row.Digest, row.Purpose, row.OriginURL, append([]string{}, row.AllowedDestinationCIDRs...), row.OriginCAPEM, row.OriginCADigest}
	}
	checks := make([]api.AppAccessCheck, len(out.Checks))
	for i, row := range out.Checks {
		checks[i] = appAccessCheck(row)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, appAccessDesiredWire{out.ProtocolVersion, out.Purpose, out.Withdrawn, out.Reason, assignments, checks})
	a.dispatchAppAccessChecks(node, out.Checks)
}

type appAccessResultWire struct {
	RequestID     uuid.UUID `json:"request_id"`
	Generation    uuid.UUID `json:"generation"`
	AppID         uuid.UUID `json:"app_id"`
	Revision      int64     `json:"revision"`
	Digest        string    `json:"digest"`
	Purpose       string    `json:"purpose"`
	DNSStatus     string    `json:"dns_status"`
	ConnectStatus string    `json:"connect_status"`
	TLSStatus     string    `json:"tls_status"`
	ErrorCode     string    `json:"error_code"`
}

func (a *AgentChannel) appAccessResult(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok || !a.appAccessAvailable(w, r) {
		return
	}
	var body appAccessResultWire
	if !decodeAppAccessAgent(w, r, &body) {
		return
	}
	requestID, err := uuid.Parse(chi.URLParam(r, "requestId"))
	if err != nil || requestID == uuid.Nil || requestID != body.RequestID {
		apierr.Write(w, r, apierr.BadRequest("invalid_request", "request correlation required"))
		return
	}
	out, err := a.appAccess.CompleteCheck(r.Context(), appAccessGateway(node), appaccess.Result{RequestID: body.RequestID, Generation: body.Generation, AppID: body.AppID, Revision: body.Revision, Digest: body.Digest, Purpose: body.Purpose, DNSStatus: body.DNSStatus, ConnectStatus: body.ConnectStatus, TLSStatus: body.TLSStatus, ErrorCode: body.ErrorCode}, a.appAccessHasEntitlement())
	if err != nil {
		apierr.Write(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, appAccessCheck(out))
}

type appAccessAppliedWire struct {
	Generation uuid.UUID `json:"generation"`
	AppID      uuid.UUID `json:"app_id"`
	Revision   int64     `json:"revision"`
	Digest     string    `json:"digest"`
	Purpose    string    `json:"purpose"`
	Status     string    `json:"status"`
	ErrorCode  string    `json:"error_code"`
}

func (a *AgentChannel) appAccessReport(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok || !a.appAccessAvailable(w, r) {
		return
	}
	var body appAccessAppliedWire
	if !decodeAppAccessAgent(w, r, &body) {
		return
	}
	out, err := a.appAccess.ReportApplied(r.Context(), appAccessGateway(node), appaccess.Applied{Generation: body.Generation, AppID: body.AppID, Revision: body.Revision, Digest: body.Digest, Purpose: body.Purpose, Status: body.Status, ErrorCode: body.ErrorCode}, a.appAccessHasEntitlement())
	if err != nil {
		apierr.Write(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, appAccessGatewayRuntime(out))
}

func (a *AgentChannel) CloseAppAccessConnector() error {
	if state := a.appAccessDispatch; state != nil {
		state.mu.Lock()
		state.closed = true
		for _, cancel := range state.active {
			cancel()
		}
		state.mu.Unlock()
	}
	if a.appAccessBroker != nil {
		return a.appAccessBroker.Close()
	}
	return nil
}

// AppAccessBroker exposes only the exact-binding origin-check dial pool to
// internal callers. It is never a browser route or an arbitrary origin dialer.
func (a *AgentChannel) AppAccessBroker() *apptransport.Broker { return a.appAccessBroker }
func (a *AgentChannel) appAccessChannel(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	if r.TLS.Version < tls.VersionTLS13 {
		apierr.Write(w, r, apierr.Forbidden("tls_version_required", "App Access channel requires TLS 1.3"))
		return
	}
	node, r, ok := a.authenticateAgent(w, r)
	if !ok || !a.appAccessAvailable(w, r) {
		return
	}
	app, err := uuid.Parse(r.Header.Get("X-App-ID"))
	if err != nil {
		apierr.Write(w, r, apierr.BadRequest("invalid_assignment", "exact app assignment headers required"))
		return
	}
	generation, err := uuid.Parse(r.Header.Get("X-App-Generation"))
	if err != nil {
		apierr.Write(w, r, apierr.BadRequest("invalid_assignment", "exact app assignment headers required"))
		return
	}
	revision, err := strconv.ParseInt(r.Header.Get("X-App-Revision"), 10, 64)
	if err != nil || revision < 1 {
		apierr.Write(w, r, apierr.BadRequest("invalid_assignment", "exact app assignment headers required"))
		return
	}
	binding := apptransport.Binding{OrgID: node.OrgID.String(), GatewayID: node.ID.String(), AppID: app.String(), Generation: generation.String(), Revision: revision, Digest: r.Header.Get("X-App-Digest"), Purpose: r.Header.Get("X-App-Purpose")}
	if binding.Purpose != "origin_check" || binding.ValidateHeaders(r.Header) != nil {
		apierr.Write(w, r, apierr.BadRequest("invalid_assignment", "exact origin-check assignment headers required"))
		return
	}
	if a.appAccessBroker == nil {
		apierr.Write(w, r, apierr.New(503, "app_access_unavailable", "App Access connector pool unavailable"))
		return
	}
	// The broker performs the first authority check before hijack, and refreshes
	// the exact certificate/assignment lease throughout idle and active lifetime.
	_ = a.appAccessBroker.Accept(w, r, binding, node.CertSerial)
}

type appAccessBrowserGatewayPort interface {
	ReportBrowserCapability(context.Context, appaccess.AuthenticatedGateway, int32) (appaccess.GatewayRuntime, error)
	DesiredBrowser(context.Context, appaccess.AuthenticatedGateway, bool) (appaccess.BrowserDesired, error)
}
type appAccessBrowserAssignmentWire struct {
	appProxyRouteWire
	Stage              string     `json:"stage"`
	OperationID        *uuid.UUID `json:"operation_id,omitempty"`
	ReadinessRequestID *uuid.UUID `json:"readiness_request_id,omitempty"`
	Deadline           *time.Time `json:"deadline,omitempty"`
}
type appAccessBrowserDesiredWire struct {
	ProtocolVersion int32                            `json:"protocol_version"`
	Purpose         string                           `json:"purpose"`
	Withdrawn       bool                             `json:"withdrawn"`
	Reason          string                           `json:"reason"`
	Assignments     []appAccessBrowserAssignmentWire `json:"assignments"`
}

func (a *AgentChannel) appAccessBrowserCapability(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	svc, ok := a.appAccess.(appAccessBrowserGatewayPort)
	if !ok {
		apierr.Write(w, r, apierr.New(503, "app_access_unavailable", "browser connector unavailable"))
		return
	}
	var body appAccessCapabilityWire
	if !decodeAppAccessAgent(w, r, &body) {
		return
	}
	if body.ProtocolVersion == nil {
		apierr.Write(w, r, apierr.BadRequest("invalid_capability", "protocol version required"))
		return
	}
	out, e := svc.ReportBrowserCapability(r.Context(), appAccessGateway(node), *body.ProtocolVersion)
	if e != nil {
		apierr.Write(w, r, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, appAccessGatewayRuntime(out))
}
func (a *AgentChannel) appAccessBrowserDesired(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	svc, ok := a.appAccess.(appAccessBrowserGatewayPort)
	if !ok {
		apierr.Write(w, r, apierr.New(503, "app_access_unavailable", "browser connector unavailable"))
		return
	}
	out, e := svc.DesiredBrowser(r.Context(), appAccessGateway(node), a.appAccessHasEntitlement())
	if e != nil {
		apierr.Write(w, r, e)
		return
	}
	wire := appAccessBrowserDesiredWire{ProtocolVersion: out.ProtocolVersion, Purpose: out.Purpose, Withdrawn: out.Withdrawn, Reason: out.Reason, Assignments: []appAccessBrowserAssignmentWire{}}
	for _, a := range out.Assignments {
		b := a.RouteBinding
		wire.Assignments = append(wire.Assignments, appAccessBrowserAssignmentWire{appProxyRouteWire: appProxyRouteWire{Binding: appProxyBindingWire{b.OrgID, b.AppID, b.GatewayID, b.Generation, b.Revision, b.AuthorityVersion, b.Digest, b.Hostname, b.Purpose}, OriginURL: a.OriginURL, Allowed: a.AllowedDestinationCIDRs, CA: a.OriginCAPEM, CADigest: a.OriginCADigest}, Stage: a.Stage, OperationID: a.OperationID, ReadinessRequestID: a.ReadinessRequestID, Deadline: a.Deadline})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, wire)
}
