package http

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
)

// fakeSSOOrgLister returns a canned org list (or error) for soleSSOOrg.
type fakeSSOOrgLister struct {
	orgs []uuid.UUID
	err  error
	// provider records what the resolver actually asked for — a resolver that ignored the
	// provider would still pass the count assertions while resolving the wrong IdP.
	provider string
}

func (f *fakeSSOOrgLister) ListEnabledSSOOrgsByProvider(_ context.Context, provider string) ([]uuid.UUID, error) {
	f.provider = provider
	return f.orgs, f.err
}

// TestSoleSSOOrgResolvesTheOnlyConfiguredOrg is the case the login page depends on: one org has
// the provider enabled, so nobody has to type a tenant slug.
func TestSoleSSOOrgResolvesTheOnlyConfiguredOrg(t *testing.T) {
	want := uuid.New()
	f := &fakeSSOOrgLister{orgs: []uuid.UUID{want}}
	got, err := soleSSOOrg(context.Background(), f, "google")
	if err != nil {
		t.Fatalf("sole configured org: unexpected error %v", err)
	}
	if got != want {
		t.Fatalf("resolved org = %v, want %v", got, want)
	}
	if f.provider != "google" {
		t.Fatalf("resolver queried provider %q, want \"google\"", f.provider)
	}
}

// TestSoleSSOOrgRejectsWhenNoneConfigured — zero configured orgs must REJECT. There is no org to
// borrow credentials from, and a redirect built from nothing is a broken IdP round-trip, not a login.
func TestSoleSSOOrgRejectsWhenNoneConfigured(t *testing.T) {
	f := &fakeSSOOrgLister{orgs: nil}
	_, err := soleSSOOrg(context.Background(), f, "google")
	if !hasCode(err, 404, "sso_not_configured") {
		t.Fatalf("no configured org: want 404 sso_not_configured, got %v", err)
	}
}

// ⛔ THE SECURITY CASE. Two orgs with the same provider enabled must REJECT, never pick.
//
// Picking either one sends this person to a DIFFERENT tenant's identity provider, and because the
// flow state records that org id, a successful round-trip would land them in an org they were never
// a member of. "First row" is an ordering accident, not an authorization decision — so the ambiguity
// is surfaced and the caller supplies the slug explicitly.
func TestSoleSSOOrgRefusesToGuessBetweenTwoOrgs(t *testing.T) {
	f := &fakeSSOOrgLister{orgs: []uuid.UUID{uuid.New(), uuid.New()}}
	got, err := soleSSOOrg(context.Background(), f, "google")
	if !hasCode(err, 400, "sso_org_ambiguous") {
		t.Fatalf("two configured orgs: want 400 sso_org_ambiguous, got %v", err)
	}
	if got != uuid.Nil {
		t.Fatalf("ambiguous resolve returned org %v — it must resolve to nothing at all", got)
	}
}

// TestSoleSSOOrgPropagatesQueryErrors — a database failure is not "nobody configured SSO". Mapping
// it to sso_not_configured would tell an operator to go configure something already configured.
func TestSoleSSOOrgPropagatesQueryErrors(t *testing.T) {
	boom := errors.New("connection refused")
	f := &fakeSSOOrgLister{err: boom}
	if _, err := soleSSOOrg(context.Background(), f, "google"); !errors.Is(err, boom) {
		t.Fatalf("query error: want it propagated, got %v", err)
	}
}

// recordingSSOPort captures the org slug the handler forwards.
type recordingSSOPort struct {
	ssoPort
	gotSlug string
	called  bool
}

func (r *recordingSSOPort) StartLogin(_ context.Context, orgSlug, _ string) (string, error) {
	r.gotSlug = orgSlug
	r.called = true
	return "https://idp.example/authorize", nil
}

// ⛔ REACHABILITY, NOT JUST BEHAVIOUR. soleSSOOrg only ever runs on an EMPTY slug, so the tests
// above prove nothing unless the handler actually produces one from a browser that sent no `org`.
// The param is a *string now: nil (omitted) and " " (whitespace) must both arrive as "".
func TestStartSsoLoginForwardsEmptySlugWhenOrgOmitted(t *testing.T) {
	blank := " "
	for _, tc := range []struct {
		name string
		org  *string
	}{
		{"omitted", nil},
		{"whitespace", &blank},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := &recordingSSOPort{}
			s := apiServer{sso: port}
			_, err := s.StartSsoLogin(context.Background(), api.StartSsoLoginRequestObject{
				Provider: api.StartSsoLoginParamsProviderGoogle,
				Params:   api.StartSsoLoginParams{Org: tc.org},
			})
			if err != nil {
				t.Fatalf("StartSsoLogin: unexpected error %v", err)
			}
			if !port.called {
				t.Fatal("port was never called — the handler short-circuited")
			}
			if port.gotSlug != "" {
				t.Fatalf("handler forwarded slug %q, want \"\" so the server derives the org", port.gotSlug)
			}
		})
	}
}

// A slug the caller DID send still goes through untouched — the explicit path is the escape hatch
// for the ambiguous case, so it must not be swallowed by the trimming.
func TestStartSsoLoginForwardsAnExplicitSlug(t *testing.T) {
	slug := "acme"
	port := &recordingSSOPort{}
	s := apiServer{sso: port}
	if _, err := s.StartSsoLogin(context.Background(), api.StartSsoLoginRequestObject{
		Provider: api.StartSsoLoginParamsProviderGoogle,
		Params:   api.StartSsoLoginParams{Org: &slug},
	}); err != nil {
		t.Fatalf("StartSsoLogin: unexpected error %v", err)
	}
	if port.gotSlug != "acme" {
		t.Fatalf("handler forwarded slug %q, want \"acme\"", port.gotSlug)
	}
}
