package idpsync

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// mockDoer serves canned responses keyed by a substring of the request URL. Each key may hold a
// queue so repeated GETs (pagination) return successive pages. No live Graph.
type mockDoer struct {
	t      *testing.T
	byURL  map[string][]cannedResp
	tokens int // count token-endpoint hits
	reqLog []string
}

type cannedResp struct {
	status int
	body   string
}

func (m *mockDoer) Do(req *http.Request) (*http.Response, error) {
	u := req.URL.String()
	m.reqLog = append(m.reqLog, u)
	if strings.Contains(u, "/oauth2/v2.0/token") {
		m.tokens++
		return jsonResp(200, `{"access_token":"tok-abc","expires_in":3600}`), nil
	}
	for key, queue := range m.byURL {
		if strings.Contains(u, key) && len(queue) > 0 {
			resp := queue[0]
			m.byURL[key] = queue[1:]
			return jsonResp(resp.status, resp.body), nil
		}
	}
	m.t.Fatalf("mockDoer: no canned response for %s", u)
	return nil, nil
}

func jsonResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func newTestProvider(m *mockDoer) *EntraProvider {
	p := NewEntraProvider("tenant-1", "client-1", "secret-1", m)
	// Point the bases at hosts the mock keys on; real values are irrelevant to the mock.
	p.graphBase = "https://graph.test"
	p.loginBase = "https://login.test"
	return p
}

func TestListGroupMembers_PaginatesAndMapsStatus(t *testing.T) {
	m := &mockDoer{t: t, byURL: map[string][]cannedResp{
		"/groups/grp-1/members": {
			{200, `{"value":[{"id":"u1","mail":"Alice@Acme.com","accountEnabled":true},{"id":"u2","mail":"","userPrincipalName":"bob@acme.com","accountEnabled":false}],"@odata.nextLink":"https://graph.test/v1.0/groups/grp-1/members/page2"}`},
		},
		"/members/page2": {
			{200, `{"value":[{"id":"u3","mail":"carol@acme.com","accountEnabled":true}]}`},
		},
	}}
	p := newTestProvider(m)

	got, err := p.ListGroupMembers(context.Background(), "grp-1")
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 flat members across 2 pages, got %d: %+v", len(got), got)
	}
	want := []DirectoryMember{
		{ExternalID: "u1", Email: "alice@acme.com", Status: StatusActive},
		{ExternalID: "u2", Email: "bob@acme.com", Status: StatusDisabled}, // mail empty → UPN fallback, lowered
		{ExternalID: "u3", Email: "carol@acme.com", Status: StatusActive},
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("member[%d] = %+v, want %+v", i, got[i], w)
		}
	}
	// Token minted once, reused across the token cache for both page fetches.
	if m.tokens != 1 {
		t.Errorf("token minted %d times, want 1 (cached)", m.tokens)
	}
}

// #0: a null accountEnabled is ambiguous (app lacks User.Read.All) — ListGroupMembers must ERROR,
// never silently map the member to active. The reconciler then fails static (no membership change).
func TestListGroupMembers_NullAccountEnabledErrors(t *testing.T) {
	m := &mockDoer{t: t, byURL: map[string][]cannedResp{
		"/groups/grp-1/members": {
			{200, `{"value":[{"id":"u1","mail":"alice@acme.com","accountEnabled":true},{"id":"u2","mail":"bob@acme.com"}]}`},
		},
	}}
	p := newTestProvider(m)
	if _, err := p.ListGroupMembers(context.Background(), "grp-1"); err == nil {
		t.Fatal("a null accountEnabled must abort the fetch (no silent-active), got nil error")
	}
}

// #4: a 404 on an @odata.nextLink CONTINUATION page is NOT ErrGroupGone — it's transient, so the
// reconciler leaves membership untouched instead of mass-deleting a large group mid-pagination.
func TestListGroupMembers_ContinuationPage404IsTransient(t *testing.T) {
	m := &mockDoer{t: t, byURL: map[string][]cannedResp{
		"/groups/grp-1/members": {
			{200, `{"value":[{"id":"u1","mail":"alice@acme.com","accountEnabled":true}],"@odata.nextLink":"https://graph.test/v1.0/groups/grp-1/members/page2"}`},
		},
		"/members/page2": {{404, `{"error":{"code":"Request_ResourceNotFound"}}`}},
	}}
	p := newTestProvider(m)
	_, err := p.ListGroupMembers(context.Background(), "grp-1")
	if err == nil {
		t.Fatal("a continuation-page 404 must be an error")
	}
	if err == ErrGroupGone {
		t.Fatal("#4 VIOLATED: a continuation-page 404 was conflated with ErrGroupGone (would mass-delete the group)")
	}
}

func TestListGroupMembers_GroupGone(t *testing.T) {
	m := &mockDoer{t: t, byURL: map[string][]cannedResp{
		"/groups/grp-x/members": {{404, `{"error":{"code":"Request_ResourceNotFound"}}`}},
	}}
	p := newTestProvider(m)

	_, err := p.ListGroupMembers(context.Background(), "grp-x")
	if err != ErrGroupGone {
		t.Fatalf("want ErrGroupGone on group 404, got %v", err)
	}
}

func TestListGroupMembers_TransientErrorNotGone(t *testing.T) {
	m := &mockDoer{t: t, byURL: map[string][]cannedResp{
		"/groups/grp-1/members": {{503, `{"error":{"code":"serviceUnavailable"}}`}},
	}}
	p := newTestProvider(m)

	_, err := p.ListGroupMembers(context.Background(), "grp-1")
	if err == nil || err == ErrGroupGone {
		t.Fatalf("503 must be a transient error (not ErrGroupGone, not nil), got %v", err)
	}
}

func TestResolveUserStatus(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   UserStatus
		errNil bool
	}{
		{"active", 200, `{"id":"u1","accountEnabled":true}`, StatusActive, true},
		{"disabled", 200, `{"id":"u1","accountEnabled":false}`, StatusDisabled, true},
		{"gone", 404, `{"error":{"code":"Request_ResourceNotFound"}}`, StatusGone, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &mockDoer{t: t, byURL: map[string][]cannedResp{
				"/users/u1": {{tc.status, tc.body}},
			}}
			p := newTestProvider(m)
			got, err := p.ResolveUserStatus(context.Background(), "u1")
			if tc.errNil && err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tc.want {
				t.Errorf("status = %v, want %v", got, tc.want)
			}
		})
	}
}
