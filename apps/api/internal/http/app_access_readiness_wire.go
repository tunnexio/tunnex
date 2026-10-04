package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"time"
)

type appProxyReadinessPort interface {
	ClaimPublicationReadiness(context.Context, appaccess.AuthenticatedProxy, string, bool) ([]appaccess.ReadinessWork, error)
	ReportPublicationReadiness(context.Context, appaccess.AuthenticatedProxy, appaccess.ReadinessReport, bool) (appaccess.PublicationOperation, error)
}
type appProxyReadinessClaimWire struct {
	InstanceToken string `json:"instance_token"`
}
type appProxyReadinessWorkWire struct {
	OperationID        uuid.UUID         `json:"operation_id"`
	Version            int64             `json:"version"`
	Route              appProxyRouteWire `json:"route"`
	ReadinessRequestID uuid.UUID         `json:"readiness_request_id"`
	Deadline           time.Time         `json:"deadline"`
	ChallengeToken     string            `json:"challenge_token"`
}
type appProxyReadinessClaimResultWire struct {
	Items []appProxyReadinessWorkWire `json:"items"`
}
type appProxyReadinessReportWire struct {
	OperationID              uuid.UUID           `json:"operation_id"`
	ExpectedOperationVersion int64               `json:"expected_operation_version"`
	Binding                  appProxyBindingWire `json:"binding"`
	ReadinessRequestID       uuid.UUID           `json:"readiness_request_id"`
	InstanceToken            string              `json:"instance_token"`
	ChallengeToken           string              `json:"challenge_token"`
	CertificateSerial        string              `json:"certificate_serial"`
	PublicDNSStatus          string              `json:"public_dns_status"`
	PublicTLSStatus          string              `json:"public_tls_status"`
	DNSStatus                string              `json:"dns_status"`
	ConnectStatus            string              `json:"connect_status"`
	TLSStatus                string              `json:"tls_status"`
	ErrorCode                string              `json:"error_code"`
}
type appProxyReadinessReportResultWire struct {
	OperationID uuid.UUID `json:"operation_id"`
	Version     int64     `json:"version"`
	Status      string    `json:"status"`
}

func appProxyRoute(r appaccess.Route) appProxyRouteWire {
	b := r.RouteBinding
	return appProxyRouteWire{Binding: appProxyBindingWire{b.OrgID, b.AppID, b.GatewayID, b.Generation, b.Revision, b.AuthorityVersion, b.Digest, b.Hostname, b.Purpose}, OriginURL: r.OriginURL, Allowed: r.AllowedDestinationCIDRs, CA: r.OriginCAPEM, CADigest: r.OriginCADigest}
}
