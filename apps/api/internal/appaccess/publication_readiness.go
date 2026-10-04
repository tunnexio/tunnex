package appaccess

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"strings"
	"time"
)

type ReadinessWork struct {
	OperationID, ReadinessRequestID uuid.UUID
	Version                         int64
	Route                           Route
	Deadline                        time.Time
	ChallengeToken                  string
}
type ReadinessReport struct {
	OperationID, ReadinessRequestID                                                  uuid.UUID
	ExpectedOperationVersion                                                         int64
	Binding                                                                          RouteBinding
	InstanceToken, ChallengeToken, CertificateSerial                                 string
	PublicDNSStatus, PublicTLSStatus, DNSStatus, ConnectStatus, TLSStatus, ErrorCode string
}

func readinessChallenge(instance string, id uuid.UUID) string {
	sum := sha256.Sum256([]byte("app-readiness\x00" + instance + "\x00" + id.String()))
	return hex.EncodeToString(sum[:])
}
func operationBinding(op sqlc.AppAccessPublicationOperation) RouteBinding {
	return RouteBinding{OrgID: op.OrgID, AppID: op.AppID, GatewayID: op.GatewayID, Generation: op.Generation, Revision: op.Revision, AuthorityVersion: op.AuthorityVersion, Digest: op.Digest, Hostname: op.Hostname, Purpose: op.Purpose}
}
func lockReadinessProxy(ctx context.Context, q *sqlc.Queries, p AuthenticatedProxy) error {
	c, e := q.LockAppAccessProxyCredential(ctx, p.CredentialID)
	if e != nil || c.RevokedAt.Valid || c.Version != p.CredentialVersion {
		return proxyUnauthenticated()
	}
	return nil
}
func (s *Service) ClaimPublicationReadiness(ctx context.Context, proxy AuthenticatedProxy, instance string, entitled bool) ([]ReadinessWork, error) {
	out := []ReadinessWork{}
	if !validAppSecret(instance, "") {
		return out, apierr.BadRequest("invalid_instance", "canonical instance token required")
	}
	if !entitled || !s.publicationDomainReadyContext(ctx) {
		return out, nil
	}
	hash := sha256.Sum256([]byte(instance))
	pid := pgtype.UUID{Bytes: proxy.CredentialID, Valid: true}
	err := s.transaction(ctx, func(q *sqlc.Queries) error {
		if e := lockReadinessProxy(ctx, q, proxy); e != nil {
			return e
		}
		count, e := q.CountClaimedAppAccessReadiness(ctx, sqlc.CountClaimedAppAccessReadinessParams{ProxyCredentialID: pid, ProxyCredentialVersion: &proxy.CredentialVersion})
		if e != nil {
			return e
		}
		candidates, e := q.ListAppAccessReadinessCandidates(ctx, sqlc.ListAppAccessReadinessCandidatesParams{ProxyCredentialID: pid, ProxyCredentialVersion: &proxy.CredentialVersion, PageLimit: 8})
		if e != nil {
			return e
		}
		for _, r := range candidates {
			if e = lockGrantOrg(ctx, q, r.OrgID); e != nil {
				return e
			}
			version, e := q.LockAppAccessApplication(ctx, sqlc.LockAppAccessApplicationParams{OrgID: r.OrgID, ID: r.AppID})
			if e != nil {
				return e
			}
			if version != r.ExpectedAppVersion {
				continue
			}
			if e = s.gateway(ctx, q, AuthenticatedGateway{OrgID: r.OrgID, GatewayID: r.GatewayID, CertSerial: r.GatewayCertSerial}); e != nil {
				continue
			}
			op, e := q.LockAppAccessPublicationOperation(ctx, sqlc.LockAppAccessPublicationOperationParams{OrgID: r.OrgID, AppID: r.AppID, OperationID: r.ID})
			if e != nil {
				return e
			}
			if !op.Deadline.After(s.now()) {
				continue
			}
			if op.Status == "queued" {
				if count >= 8 {
					continue
				}
				op, e = q.ClaimAppAccessPublicationReadiness(ctx, sqlc.ClaimAppAccessPublicationReadinessParams{OrgID: op.OrgID, AppID: op.AppID, OperationID: op.ID, ExpectedVersion: op.Version, ProxyCredentialID: pid, ProxyCredentialVersion: &proxy.CredentialVersion, ProxyInstanceTokenHash: hash[:]})
				if e != nil {
					return e
				}
				count++
			} else if op.Status != "checking" || subtle.ConstantTimeCompare(op.ProxyInstanceTokenHash, hash[:]) != 1 {
				continue
			}
			out = append(out, ReadinessWork{OperationID: op.ID, ReadinessRequestID: op.ReadinessRequestID, Version: op.Version, Deadline: op.Deadline, ChallengeToken: readinessChallenge(instance, op.ReadinessRequestID), Route: Route{RouteBinding: operationBinding(op), OriginURL: r.OriginUrl, AllowedDestinationCIDRs: append([]string{}, r.AllowedDestinationCidrs...), OriginCAPEM: r.OriginCaPem, OriginCADigest: r.OriginCaDigest}})
		}
		return nil
	})
	return out, err
}
func validReadinessStage(v string) bool { return v == "pending" || v == "passed" || v == "failed" }
func validReadinessError(v string) bool {
	switch v {
	case "", "dns_failed", "target_refused", "connect_failed", "tls_failed", "http_failed", "deadline_exceeded", "assignment_changed", "connector_failed", "public_dns_failed", "public_tls_failed", "public_challenge_failed", "capability_unavailable", "origin_check_stale", "publication_changed", "proxy_unavailable":
		return true
	}
	return false
}
func (s *Service) ReportPublicationReadiness(ctx context.Context, proxy AuthenticatedProxy, input ReadinessReport, entitled bool) (PublicationOperation, error) {
	var out PublicationOperation
	if !validAppSecret(input.InstanceToken, "") || input.OperationID == uuid.Nil || input.ReadinessRequestID == uuid.Nil || input.ExpectedOperationVersion < 1 || !validReadinessStage(input.PublicDNSStatus) || !validReadinessStage(input.PublicTLSStatus) || !validReadinessStage(input.DNSStatus) || !validReadinessStage(input.ConnectStatus) || !(validReadinessStage(input.TLSStatus) || input.TLSStatus == "skipped") || !validReadinessError(input.ErrorCode) {
		return out, apierr.BadRequest("invalid_readiness", "invalid bounded readiness report")
	}
	if !entitled || !s.publicationDomainReadyContext(ctx) {
		return out, appAuthorityUnavailable()
	}
	hash := sha256.Sum256([]byte(input.InstanceToken))
	pid := pgtype.UUID{Bytes: proxy.CredentialID, Valid: true}
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		if e := lockReadinessProxy(ctx, q, proxy); e != nil {
			return e
		}
		stored, e := q.GetAppAccessReadinessOperationByID(ctx, input.OperationID)
		if errors.Is(e, pgx.ErrNoRows) {
			return notFound()
		}
		if e != nil {
			return e
		}
		if operationBinding(stored) != input.Binding || stored.ReadinessRequestID != input.ReadinessRequestID || stored.GatewayCertSerial != input.CertificateSerial || !stored.ProxyCredentialID.Valid || uuid.UUID(stored.ProxyCredentialID.Bytes) != proxy.CredentialID || stored.ProxyCredentialVersion == nil || *stored.ProxyCredentialVersion != proxy.CredentialVersion || subtle.ConstantTimeCompare(stored.ProxyInstanceTokenHash, hash[:]) != 1 || subtle.ConstantTimeCompare([]byte(readinessChallenge(input.InstanceToken, input.ReadinessRequestID)), []byte(input.ChallengeToken)) != 1 {
			return appAuthorityUnavailable()
		}
		if e = lockGrantOrg(ctx, q, stored.OrgID); e != nil {
			return e
		}
		if _, e = q.LockAppAccessApplication(ctx, sqlc.LockAppAccessApplicationParams{OrgID: stored.OrgID, ID: stored.AppID}); e != nil {
			return e
		}
		if e = s.gateway(ctx, q, AuthenticatedGateway{OrgID: stored.OrgID, GatewayID: stored.GatewayID, CertSerial: input.CertificateSerial}); e != nil {
			return e
		}
		op, e := q.LockAppAccessPublicationOperation(ctx, sqlc.LockAppAccessPublicationOperationParams{OrgID: stored.OrgID, AppID: stored.AppID, OperationID: stored.ID})
		if e != nil {
			return e
		}
		if op.Status != "checking" {
			out = s.projectPublicationOperation(op)
			return nil
		}
		if op.Version != input.ExpectedOperationVersion || !op.Deadline.After(s.now()) {
			return conflict()
		}
		enabled, e := q.LockAppAccessSettings(ctx, op.OrgID)
		if e != nil || !enabled {
			return appAuthorityUnavailable()
		}
		revision, e := q.GetAppAccessRevision(ctx, sqlc.GetAppAccessRevisionParams{OrgID: op.OrgID, AppID: op.AppID, Revision: op.Revision})
		if e != nil {
			return e
		}
		requiredTLS := "skipped"
		if strings.HasPrefix(revision.OriginUrl, "https://") {
			requiredTLS = "passed"
		}
		success := input.PublicDNSStatus == "passed" && input.PublicTLSStatus == "passed" && input.DNSStatus == "passed" && input.ConnectStatus == "passed" && input.TLSStatus == requiredTLS && input.ErrorCode == ""
		status := "failed"
		code := input.ErrorCode
		if success {
			status = "checking"
		} else if code == "" {
			code = "connector_failed"
		}
		completed, e := q.CompleteAppAccessPublicationReadiness(ctx, sqlc.CompleteAppAccessPublicationReadinessParams{OrgID: op.OrgID, AppID: op.AppID, OperationID: op.ID, ExpectedVersion: op.Version, ReadinessRequestID: input.ReadinessRequestID, ProxyCredentialID: pid, ProxyCredentialVersion: &proxy.CredentialVersion, ProxyInstanceTokenHash: hash[:], GatewayCertSerial: input.CertificateSerial, PublicDnsStatus: input.PublicDNSStatus, PublicTlsStatus: input.PublicTLSStatus, ConnectorDnsStatus: input.DNSStatus, ConnectorConnectStatus: input.ConnectStatus, ConnectorTlsStatus: input.TLSStatus, ErrorCode: code, Status: status})
		if errors.Is(e, pgx.ErrNoRows) {
			return conflict()
		}
		if e != nil {
			return e
		}
		if success {
			n, e := q.ActivateAppAccessServingPublication(ctx, sqlc.ActivateAppAccessServingPublicationParams{OrgID: op.OrgID, AppID: op.AppID, OperationID: op.ID, ExpectedVersion: completed.Version})
			if e != nil {
				return e
			}
			if n == 1 {
				completed, e = q.MarkAppAccessPublicationActivated(ctx, sqlc.MarkAppAccessPublicationActivatedParams{OrgID: op.OrgID, AppID: op.AppID, OperationID: op.ID, ExpectedVersion: completed.Version})
			} else {
				completed, e = q.FailAppAccessPublicationOperation(ctx, sqlc.FailAppAccessPublicationOperationParams{OrgID: op.OrgID, AppID: op.AppID, OperationID: op.ID, ExpectedVersion: completed.Version, ErrorCode: "assignment_changed"})
			}
			if e != nil {
				return e
			}
		}
		out = s.projectPublicationOperation(completed)
		return audit(ctx, q, op.OrgID, op.ActorUserID, op.AppID.String(), "app_access.publication_"+completed.Status, completed.ExpectedAppVersion)
	})
	return out, e
}
