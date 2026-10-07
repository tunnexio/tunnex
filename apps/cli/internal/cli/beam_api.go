package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/cli/internal/beamapi"
	"github.com/tunnexio/tunnex/packages/apptransport"
	beamtransport "github.com/tunnexio/tunnex/packages/apptransport/beam"
)

// These private wire types are kept separate from the printable CLI projection.
// Connector responses, origin CA and local targets never pass through the output encoder.
type beamPolicy struct {
	Capabilities     []string `json:"capabilities"`
	OpenForAllUsers  bool     `json:"open_for_all_users"`
	Enabled          bool     `json:"enabled"`
	CanPublish       bool     `json:"can_publish"`
	DomainReady      bool     `json:"domain_ready"`
	ProtocolVersion  int      `json:"protocol_version"`
	MinClientVersion string   `json:"min_client_version"`
	MaxDuration      int      `json:"max_duration_seconds"`
	MaxShares        int      `json:"max_shares"`
	RequireMFA       bool     `json:"require_mfa"`
}
type beamGrant struct {
	Kind string `json:"subject_kind"`
	ID   string `json:"subject_id"`
}
type beamTarget struct {
	Protocol string      `json:"protocol"`
	Address  string      `json:"address"`
	Port     int         `json:"port"`
	CAPEM    string      `json:"ca_pem,omitempty"`
	Routes   []beamRoute `json:"routes,omitempty"`
}
type beamRoute struct {
	PathPrefix string     `json:"path_prefix"`
	Target     beamTarget `json:"target"`
}

func (t beamTarget) transport() beamtransport.Target {
	out := beamtransport.Target{Protocol: t.Protocol, Address: t.Address, Port: t.Port, CAPEM: t.CAPEM}
	for _, r := range t.Routes {
		out.Routes = append(out.Routes, beamtransport.Route{PathPrefix: r.PathPrefix, Target: r.Target.transport()})
	}
	return out
}

type beamShare struct {
	ID               string      `json:"id"`
	OrgID            string      `json:"org_id"`
	PublisherID      string      `json:"publisher_id"`
	Name             string      `json:"name"`
	Hostname         string      `json:"hostname"`
	URL              string      `json:"url"`
	State            string      `json:"state"`
	Connectivity     string      `json:"connectivity"`
	Version          int64       `json:"version"`
	AuthorityVersion int64       `json:"authority_version"`
	ExpiresAt        time.Time   `json:"expires_at"`
	CanManage        bool        `json:"can_manage"`
	Target           *beamTarget `json:"target,omitempty"`
	Grants           []beamGrant `json:"grants,omitempty"`
}
type beamCreate struct {
	ProjectID      string      `json:"project_id,omitempty"`
	Name           string      `json:"name"`
	Target         beamTarget  `json:"target"`
	Duration       int         `json:"duration_seconds"`
	Grants         []beamGrant `json:"grants"`
	IdempotencyKey string      `json:"idempotency_key"`
}
type beamAction struct {
	Action          string     `json:"action"`
	ExpectedVersion int64      `json:"expected_version"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}
type beamConnectorWire struct {
	Binding struct {
		OrgID            string `json:"org_id"`
		AppID            string `json:"app_id"`
		GatewayID        string `json:"gateway_id"`
		Generation       string `json:"generation"`
		Revision         int64  `json:"revision"`
		AuthorityVersion int64  `json:"authority_version"`
		Digest           string `json:"digest"`
		Hostname         string `json:"hostname"`
		Purpose          string `json:"purpose"`
	} `json:"binding"`
	ShareVersion         int64     `json:"share_version"`
	ProxyURL             string    `json:"proxy_url"`
	ServerName           string    `json:"proxy_server_name"`
	CAPEM                string    `json:"ca_pem"`
	CertificatePEM       string    `json:"certificate_pem"`
	ExpiresAt            time.Time `json:"expires_at"`
	CertificateExpiresAt time.Time `json:"certificate_expires_at"`
}

func (c beamConnectorWire) binding() apptransport.Binding {
	b := c.Binding
	return apptransport.Binding{OrgID: b.OrgID, AppID: b.AppID, GatewayID: b.GatewayID, Generation: b.Generation, Revision: b.Revision, AuthorityVersion: b.AuthorityVersion, Digest: b.Digest, Hostname: b.Hostname, Purpose: b.Purpose}
}

type beamSharePage struct {
	Items  []beamShare `json:"items"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
	Quota  *struct {
		ActiveShares int `json:"active_shares"`
		MaxShares    int `json:"max_shares"`
	} `json:"quota,omitempty"`
}
type beamAudience struct {
	Users []struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"users"`
	Groups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"groups"`
}

type beamAPI interface {
	Policy(context.Context, string) (beamPolicy, error)
	Audience(context.Context, string) (beamAudience, error)
	List(context.Context, string, int) (beamSharePage, error)
	Get(context.Context, string, string) (beamShare, error)
	Create(context.Context, string, beamCreate) (beamShare, error)
	Action(context.Context, string, string, beamAction) (beamShare, error)
	Issue(context.Context, string, string, int64, string) (beamConnectorWire, error)
	Heartbeat(context.Context, string, string, string, bool) (beamShare, error)
}
type beamHTTPAPI struct {
	credential Credential
	client     *http.Client
}

func newBeamHTTPAPI(c Credential) (beamAPI, error) {
	u, e := url.Parse(c.Server)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))) || strings.TrimSpace(c.Token) == "" {
		return nil, errors.New("invalid stored server or login; run 'tunnex login' with the canonical HTTPS server")
	}
	return &beamHTTPAPI{c, &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func beamPath(org string) string { return "/api/v1/organizations/" + url.PathEscape(org) + "/beam" }

type beamAPIError struct {
	status int
	code   string
}

func (e *beamAPIError) Error() string {
	switch e.status {
	case 401:
		return "Beam login is no longer valid; run 'tunnex login'"
	case 403:
		return "Beam access denied by current sharing policy or publishing authority"
	case 404:
		return "Beam share unavailable to this login; resume requires the original publishing credential"
	case 409:
		return "Beam state changed; fetch the current share before trying again"
	case 429:
		if e.code == "beam_quota_reached" {
			return "Beam share limit reached; stop an old share or wait for its expiry"
		}
		return "Beam capacity reached; wait before retrying"
	}
	if e.status == 400 {
		return "Beam request rejected; check the target, reviewers, duration and sharing policy"
	}
	if e.status >= 500 {
		return "Beam authority is temporarily unavailable; serving has no local authorization fallback"
	}
	return fmt.Sprintf("Beam request failed (HTTP %d)", e.status)
}
func beamTransient(e error) bool {
	var a *beamAPIError
	if errors.As(e, &a) {
		return a.status == 502 || a.status == 503 || a.status == 504
	}
	return errors.Is(e, errBeamNetwork)
}

var errBeamNetwork = errors.New("could not reach Beam authority")

func (a *beamHTTPAPI) request(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		b, e := json.Marshal(input)
		if e != nil {
			return errors.New("invalid Beam request")
		}
		if len(b) > 32<<10 {
			return errors.New("Beam request exceeded the safe size limit")
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.credential.Server, "/")+path, body)
	if e != nil {
		return errors.New("invalid Beam server")
	}
	req.Header.Set("Authorization", "Bearer "+a.credential.Token)
	req.Header.Set("Accept", "application/json")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, e := a.client.Do(req)
	if e != nil {
		return errBeamNetwork
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
	if e != nil {
		return errBeamNetwork
	}
	if len(b) > 2<<20 {
		return errors.New("Beam response exceeded the safe size limit")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var env envelope
		_ = json.Unmarshal(b, &env)
		return &beamAPIError{res.StatusCode, env.Error.Code}
	}
	if output == nil {
		return nil
	}
	if json.Unmarshal(b, output) != nil {
		return errors.New("invalid Beam response")
	}
	return nil
}
func (a *beamHTTPAPI) Policy(c context.Context, o string) (v beamPolicy, e error) {
	e = a.request(c, "GET", beamPath(o)+"/policy", nil, &v)
	return
}
func (a *beamHTTPAPI) Audience(c context.Context, o string) (v beamAudience, e error) {
	e = a.request(c, "GET", beamPath(o)+"/audience", nil, &v)
	return
}
func (a *beamHTTPAPI) List(c context.Context, o string, n int) (v beamSharePage, e error) {
	e = a.request(c, "GET", beamPath(o)+fmt.Sprintf("/shares?limit=20&offset=%d", n), nil, &v)
	return
}
func (a *beamHTTPAPI) Get(c context.Context, o, id string) (v beamShare, e error) {
	e = a.request(c, "GET", beamPath(o)+"/shares/"+url.PathEscape(id), nil, &v)
	return
}
func (a *beamHTTPAPI) Create(c context.Context, o string, i beamCreate) (v beamShare, e error) {
	grants := make([]beamapi.BeamGrant, 0, len(i.Grants))
	for _, g := range i.Grants {
		id, err := uuid.Parse(g.ID)
		if err != nil {
			return v, errors.New("invalid Beam reviewer")
		}
		grants = append(grants, beamapi.BeamGrant{SubjectId: id, SubjectKind: beamapi.BeamGrantSubjectKind(g.Kind)})
	}
	_, err := uuid.Parse(i.IdempotencyKey)
	if err != nil {
		return v, errors.New("invalid Beam idempotency key")
	}
	if err := beamtransport.ValidateTarget(i.Target.transport()); err != nil {
		return v, err
	}
	if i.ProjectID != "" {
		if _, err := beamUUID(i.ProjectID); err != nil {
			return v, err
		}
	}
	e = a.request(c, "POST", beamPath(o)+"/shares", i, &v)
	return
}
func (a *beamHTTPAPI) Action(c context.Context, o, id string, i beamAction) (v beamShare, e error) {
	if i.ExpectedVersion <= 0 || int64(int(i.ExpectedVersion)) != i.ExpectedVersion {
		return v, errors.New("invalid Beam share revision")
	}
	e = a.request(c, "POST", beamPath(o)+"/shares/"+url.PathEscape(id)+"/actions", beamapi.BeamActionInput{Action: beamapi.BeamActionInputAction(i.Action), ExpectedVersion: int(i.ExpectedVersion), ExpiresAt: i.ExpiresAt}, &v)
	return
}
func (a *beamHTTPAPI) Issue(c context.Context, o, id string, version int64, csr string) (v beamConnectorWire, e error) {
	e = a.request(c, "POST", beamPath(o)+"/shares/"+url.PathEscape(id)+"/connector", map[string]any{"expected_version": version, "csr_pem": csr, "capabilities": []string{beamtransport.PathRoutesCapability}}, &v)
	return
}
func (a *beamHTTPAPI) Heartbeat(c context.Context, o, id, g string, ready bool) (v beamShare, e error) {
	generation, err := uuid.Parse(g)
	if err != nil {
		return v, errors.New("invalid Beam generation")
	}
	e = a.request(c, "POST", beamPath(o)+"/shares/"+url.PathEscape(id)+"/heartbeat", beamapi.BeamHeartbeatInput{Generation: generation, OriginReady: ready}, &v)
	return
}
