// Package cp is a THIN typed client for the Tunnex control-plane HTTP API — the operator's ONLY way to reach
// Tunnex (THE HARD RULE: an API client, never a DB writer). It is deliberately not the generated full-spec
// client: the operator touches ~8 endpoints, and the module's whole discipline is lightness (the same
// argument as no-client-go in the agent). It authenticates with the operator's MACHINE credential (S10.2
// Slice 1, `tnxm_` bearer) and parses the CP's `{error:{code,message}}` so the reconciler can render an
// HONEST CR status naming the CP's own code + message verbatim.
package cp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client calls the CP as a machine principal for one org.
type Client struct {
	base  string
	token string
	org   string
	http  *http.Client
}

// New builds a client for baseURL (e.g. https://cp.example.com), a `tnxm_` machine token, and the org the
// operator manages.
func New(baseURL, token, orgID string) *Client {
	return &Client{
		base:  strings.TrimRight(baseURL, "/"),
		token: token,
		org:   orgID,
		http:  &http.Client{Timeout: 30 * time.Second},
	}
}

// APIError is a CP 4xx — a CLIENT error (bad request / edition_required / conflict / not-found). The
// reconciler turns it into a NON-Ready CR condition naming Code + Message verbatim (honest status). It is
// DISTINCT from a transport or 5xx error (returned as a plain error → retryable, keep-last). IsAPIError lets
// the reconciler branch: a 4xx is the caller's fault (surface it, don't spin); a 5xx/transport error is the
// CP's (requeue, hold last-good).
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("cp %d %s: %s", e.Status, e.Code, e.Message) }

// AsAPIError returns the *APIError if err is one (a CP 4xx), else nil.
func AsAPIError(err error) *APIError {
	var e *APIError
	if ok := asErr(err, &e); ok {
		return e
	}
	return nil
}

func asErr(err error, target **APIError) bool {
	for err != nil {
		if e, ok := err.(*APIError); ok {
			*target = e
			return true
		}
		type unwrap interface{ Unwrap() error }
		u, ok := err.(unwrap)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func (c *Client) orgPath(suffix string) string {
	return "/api/v1/organizations/" + c.org + suffix
}

// do sends a request with the machine bearer; decodes `out` on 2xx; returns *APIError on 4xx; a plain
// (retryable) error on transport failure or 5xx. A non-empty cause is sent as X-Tunnex-Cause so an audited
// mutation names the CR that drove it (D2 cond 2) instead of just the credential.
func (c *Client) do(ctx context.Context, method, path, cause string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if cause != "" {
		req.Header.Set("X-Tunnex-Cause", cause)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err // transport failure → retryable (keep-last)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if out == nil {
			return nil
		}
		return json.NewDecoder(resp.Body).Decode(out)
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return &APIError{Status: resp.StatusCode, Code: e.Error.Code, Message: e.Error.Message}
	default:
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("cp %d: %s", resp.StatusCode, strings.TrimSpace(string(b))) // 5xx → retryable
	}
}

// ── wire types (mirror the OpenAPI response/request shapes; only the fields the operator needs) ──────────

type Cluster struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	VipRange    string `json:"vip_range"`
	ServiceCidr string `json:"service_cidr"`
	DnsZone     string `json:"dns_zone"`
	DnsVip      string `json:"dns_vip"`
	SiteID      string `json:"site_id"`
}

type Service struct {
	ID        string `json:"id"`
	ClusterID string `json:"cluster_id"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Vip       string `json:"vip"`
	Fqdn      string `json:"fqdn"`
}

// Member / Group / Site are the READ-ONLY lookup shapes the grant + cluster reconcilers use to resolve a
// human-friendly CR subject (an email / group name / site name) to the UUID the CP mutation verbs want. They
// hit existing GET endpoints — the operator stays an API CLIENT, no new CP surface (THE HARD RULE).
type Member struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Site struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Rule struct {
	ID                string  `json:"id"`
	SrcKind           string  `json:"src_kind"`
	SrcUserID         *string `json:"src_user_id"`
	SrcGroupID        *string `json:"src_group_id"`
	SrcSiteID         *string `json:"src_site_id"`
	SrcCidr           *string `json:"src_cidr"`
	DstKind           string  `json:"dst_kind"`
	DstK8sServiceID   *string `json:"dst_k8s_service_id"`
	ManagedByOperator bool    `json:"managed_by_operator"`
}

type RegisterClusterRequest struct {
	SiteID      string `json:"site_id"`
	Name        string `json:"name"`
	VipRange    string `json:"vip_range"`
	ServiceCidr string `json:"service_cidr"`
	DnsZone     string `json:"dns_zone"`
}

type ExposeServiceRequest struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Protocol  string `json:"protocol"`
	PortLow   int32  `json:"port_low"`
	PortHigh  int32  `json:"port_high"`
}

type CreateGrantRequest struct {
	SrcKind         string  `json:"src_kind"`
	SrcUserID       *string `json:"src_user_id,omitempty"`
	SrcGroupID      *string `json:"src_group_id,omitempty"`
	SrcSiteID       *string `json:"src_site_id,omitempty"`
	SrcCidr         *string `json:"src_cidr,omitempty"`
	DstKind         string  `json:"dst_kind"`
	DstK8sServiceID *string `json:"dst_k8s_service_id,omitempty"`
	ExpiresAt       *string `json:"expires_at,omitempty"`
}

// ── methods (the operator's bounded surface) ────────────────────────────────────────────────────────────

// ListClusters returns the org's registered clusters (for idempotent reconcile: find-by-name before create).
func (c *Client) ListClusters(ctx context.Context) ([]Cluster, error) {
	var out []Cluster
	return out, c.do(ctx, http.MethodGet, c.orgPath("/k8s/clusters"), "", nil, &out)
}

// RegisterCluster registers a cluster (Collect/OrgRanges disjointness is enforced CP-side).
func (c *Client) RegisterCluster(ctx context.Context, r RegisterClusterRequest) (Cluster, error) {
	var out Cluster
	return out, c.do(ctx, http.MethodPost, c.orgPath("/k8s/clusters"), "", r, &out)
}

// GetCluster fetches one cluster by id — the AUTHORITATIVE confirm-by-ID (S10.2 C2): found=false ONLY on a
// CP 404 (truly gone); a transport/5xx failure returns an error (keep-last), never a false "gone" the way a
// spuriously-empty LIST could. Used to gate a drift-recreate so a glitchy list can't spawn a duplicate.
func (c *Client) GetCluster(ctx context.Context, id string) (Cluster, bool, error) {
	var out Cluster
	err := c.do(ctx, http.MethodGet, c.orgPath("/k8s/clusters/"+id), "", nil, &out)
	if e := AsAPIError(err); e != nil && e.Status == http.StatusNotFound {
		return Cluster{}, false, nil
	}
	if err != nil {
		return Cluster{}, false, err
	}
	return out, true, nil
}

// GetService fetches one exposed Service by id — the confirm-by-ID analog for services (S10.2 C2).
func (c *Client) GetService(ctx context.Context, id string) (Service, bool, error) {
	var out Service
	err := c.do(ctx, http.MethodGet, c.orgPath("/k8s/services/"+id), "", nil, &out)
	if e := AsAPIError(err); e != nil && e.Status == http.StatusNotFound {
		return Service{}, false, nil
	}
	if err != nil {
		return Service{}, false, err
	}
	return out, true, nil
}

// DeregisterCluster removes a cluster (full-sweep cascade, audited CP-side; cause names the CR).
func (c *Client) DeregisterCluster(ctx context.Context, clusterID, cause string) error {
	return c.do(ctx, http.MethodDelete, c.orgPath("/k8s/clusters/"+clusterID), cause, nil, nil)
}

// ListServices returns every exposed Service in the org (find-by-name for idempotent reconcile).
func (c *Client) ListServices(ctx context.Context) ([]Service, error) {
	var out []Service
	return out, c.do(ctx, http.MethodGet, c.orgPath("/k8s/services"), "", nil, &out)
}

// ExposeService exposes a Service in a cluster (M8/M9: a single specific port; the CP refuses all-ports).
func (c *Client) ExposeService(ctx context.Context, clusterID string, r ExposeServiceRequest) (Service, error) {
	var out Service
	return out, c.do(ctx, http.MethodPost, c.orgPath("/k8s/clusters/"+clusterID+"/services"), "", r, &out)
}

// UnexposeService withdraws a Service (audited CP-side; cause names the CR).
func (c *Client) UnexposeService(ctx context.Context, serviceID, cause string) error {
	return c.do(ctx, http.MethodDelete, c.orgPath("/k8s/services/"+serviceID), cause, nil, nil)
}

// ListPolicies returns the org's policy rules — for grant idempotence-by-identity (S10.2 M2): find an
// existing MANAGED rule matching this grant before creating, so a status-write failure after a prior create
// doesn't double-place an (unnamed) rule.
func (c *Client) ListPolicies(ctx context.Context) ([]Rule, error) {
	var out []Rule
	return out, c.do(ctx, http.MethodGet, c.orgPath("/policies"), "", nil, &out)
}

// CreateGrant creates a policy rule reaching an exposed Service (ENTERPRISE — a 403 edition_required in the
// open build comes back as an *APIError the reconciler surfaces verbatim).
func (c *Client) CreateGrant(ctx context.Context, r CreateGrantRequest) (Rule, error) {
	var out Rule
	return out, c.do(ctx, http.MethodPost, c.orgPath("/policies"), "", r, &out)
}

// DeleteGrant deletes a policy rule (audited CP-side; cause names the CR).
func (c *Client) DeleteGrant(ctx context.Context, ruleID, cause string) error {
	return c.do(ctx, http.MethodDelete, c.orgPath("/policies/"+ruleID), cause, nil, nil)
}

// ── read-only lookups (resolve a friendly CR subject/site name to the CP's UUID) ────────────────────────────

// ListSites resolves spec.Site (cluster) / a site-kind grant subject: name -> id.
func (c *Client) ListSites(ctx context.Context) ([]Site, error) {
	var out []Site
	return out, c.do(ctx, http.MethodGet, c.orgPath("/sites"), "", nil, &out)
}

// ListMembers resolves a user-kind grant subject: email -> user id.
func (c *Client) ListMembers(ctx context.Context) ([]Member, error) {
	var out []Member
	return out, c.do(ctx, http.MethodGet, c.orgPath("/members"), "", nil, &out)
}

// ListGroups resolves a group-kind grant subject: name -> group id.
func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	var out []Group
	return out, c.do(ctx, http.MethodGet, c.orgPath("/groups"), "", nil, &out)
}
