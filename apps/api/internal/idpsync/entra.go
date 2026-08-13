package idpsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// EntraProvider is the Microsoft Entra (Azure AD) DirectoryProvider — the FIRST implementation.
// Everything Entra-specific is contained here and never leaks past DirectoryProvider:
//   - APP-CRED TOKEN: OAuth2 client_credentials against login.microsoftonline.com/{tenant}, cached
//     until near expiry (mu-guarded).
//   - GRAPH PAGINATION: the members endpoint returns @odata.nextLink pages; ListGroupMembers loops
//     them and returns one flat slice.
//   - DISABLED-vs-GONE: Graph `accountEnabled=false` → StatusDisabled; a 404 on the user → StatusGone;
//     a 404 on the group → ErrGroupGone.
//
// httpDoer + the base URLs are injectable so unit tests drive canned Graph JSON with NO live Graph.
type EntraProvider struct {
	tenantID     string
	clientID     string
	clientSecret string

	http      httpDoer
	graphBase string // default https://graph.microsoft.com
	loginBase string // default https://login.microsoftonline.com
	now       func() time.Time

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// NewEntraProvider builds the provider. doer defaults to http.DefaultClient; the base URLs default
// to the real Microsoft hosts (tests override all three).
func NewEntraProvider(tenantID, clientID, clientSecret string, doer httpDoer) *EntraProvider {
	if doer == nil {
		doer = http.DefaultClient
	}
	return &EntraProvider{
		tenantID: tenantID, clientID: clientID, clientSecret: clientSecret,
		http:      doer,
		graphBase: "https://graph.microsoft.com",
		loginBase: "https://login.microsoftonline.com",
		now:       time.Now,
	}
}

// --- token (client_credentials, cached) ---

func (e *EntraProvider) accessToken(ctx context.Context) (string, error) {
	// Fast path: a cached, unexpired token — held only for the map read, NOT across the HTTP call
	// below (#8: holding the mutex across the token round-trip serialized every concurrent Graph
	// fetch behind one network call).
	e.mu.Lock()
	if e.token != "" && e.now().Before(e.tokenExp) {
		t := e.token
		e.mu.Unlock()
		return t, nil
	}
	e.mu.Unlock()

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {e.clientID},
		"client_secret": {e.clientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", e.loginBase, e.tenantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := e.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("entra token: status %d", resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("entra token: empty access_token")
	}
	// Re-acquire only to publish the freshly-minted token. A concurrent refresh may mint twice
	// (harmless); neither call holds the lock across its HTTP round-trip.
	e.mu.Lock()
	e.token = tok.AccessToken
	// Refresh a minute early so an in-flight call never uses a just-expired token.
	e.tokenExp = e.now().Add(time.Duration(tok.ExpiresIn)*time.Second - time.Minute)
	t := e.token
	e.mu.Unlock()
	return t, nil
}

// graphGet issues an authenticated GET to a Graph URL (absolute, e.g. a nextLink) or a path under
// graphBase. Returns the raw *http.Response for the caller to decode / inspect status.
func (e *EntraProvider) graphGet(ctx context.Context, rawURL string) (*http.Response, error) {
	tok, err := e.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = e.graphBase + rawURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	return e.http.Do(req)
}

// --- DirectoryProvider ---

type graphUser struct {
	ID                string `json:"id"`
	Mail              string `json:"mail"`
	UserPrincipalName string `json:"userPrincipalName"`
	AccountEnabled    *bool  `json:"accountEnabled"`
}

// errAccountEnabledMissing is returned when Graph gives a null accountEnabled — the app can enumerate
// members but not read their account state (typically GroupMember.Read.All granted, User.Read.All
// NOT). A null is AMBIGUOUS, not "active": silently treating it as active is a deprovision fail-open
// (a disabled user would read active and never be swept). So a null aborts the fetch → the reconciler
// treats it as a transient failure → FAIL-STATIC (no membership change) + degraded health, surfacing
// the misconfiguration instead of silently keeping offboarded users live.
var errAccountEnabledMissing = errors.New("entra: accountEnabled not readable — grant the app User.Read.All (Application) so disabled users can be detected")

func statusOf(accountEnabled *bool) (UserStatus, error) {
	if accountEnabled == nil {
		return StatusActive, errAccountEnabledMissing
	}
	if !*accountEnabled {
		return StatusDisabled, nil
	}
	return StatusActive, nil
}

func emailOf(u graphUser) string {
	if u.Mail != "" {
		return strings.ToLower(u.Mail)
	}
	return strings.ToLower(u.UserPrincipalName) // Entra guests / no-mailbox users fall back to UPN
}

// ListGroupMembers loops the Graph nextLink pages and returns the flat member set. Only user
// members are requested (`/members/microsoft.graph.user` filters out nested groups / service
// principals). A 404 on the group → ErrGroupGone.
func (e *EntraProvider) ListGroupMembers(ctx context.Context, groupID string) ([]DirectoryMember, error) {
	next := fmt.Sprintf("/v1.0/groups/%s/members/microsoft.graph.user?$select=id,mail,userPrincipalName,accountEnabled&$top=999", url.PathEscape(groupID))
	var out []DirectoryMember
	firstPage := true // only a 404 on the GROUP endpoint means gone; a 404 on a continuation is transient
	for next != "" {
		resp, err := e.graphGet(ctx, next)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close() //nolint:errcheck
			if firstPage {
				return nil, ErrGroupGone
			}
			// #4: a 404 on an @odata.nextLink continuation is NOT authoritative-empty — treating it
			// as ErrGroupGone would mass-delete a large group mid-pagination. Transient → fail-static.
			return nil, fmt.Errorf("entra list group members: 404 on a continuation page (transient, not group-gone)")
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close() //nolint:errcheck
			return nil, fmt.Errorf("entra list group members: status %d", resp.StatusCode)
		}
		var page struct {
			Value    []graphUser `json:"value"`
			NextLink string      `json:"@odata.nextLink"`
		}
		derr := json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close() //nolint:errcheck
		if derr != nil {
			return nil, derr
		}
		for _, u := range page.Value {
			// #0: a null accountEnabled is ambiguous → abort the fetch (transient → fail-static),
			// never silently keep a possibly-disabled member as active.
			st, serr := statusOf(u.AccountEnabled)
			if serr != nil {
				return nil, serr
			}
			out = append(out, DirectoryMember{ExternalID: u.ID, Email: emailOf(u), Status: st})
		}
		firstPage = false
		next = page.NextLink
	}
	return out, nil
}

// ResolveUserStatus reports active / disabled / gone for a user by external id. A 404 → StatusGone.
func (e *EntraProvider) ResolveUserStatus(ctx context.Context, externalID string) (UserStatus, error) {
	resp, err := e.graphGet(ctx, fmt.Sprintf("/v1.0/users/%s?$select=id,accountEnabled", url.PathEscape(externalID)))
	if err != nil {
		return StatusActive, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode == http.StatusNotFound {
		return StatusGone, nil
	}
	if resp.StatusCode != http.StatusOK {
		return StatusActive, fmt.Errorf("entra resolve user: status %d", resp.StatusCode)
	}
	var u graphUser
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return StatusActive, err
	}
	// #0: null accountEnabled is ambiguous — surface the error so the caller fails static, never
	// silently reports active for a user whose state we could not read.
	return statusOf(u.AccountEnabled)
}
