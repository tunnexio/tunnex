package idpsync

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"
)

const (
	adminDirectoryGroupsScope = "https://www.googleapis.com/auth/admin.directory.group.readonly"
	adminDirectoryUsersScope  = "https://www.googleapis.com/auth/admin.directory.user.readonly"
)

type googleServiceAccount struct {
	Type         string `json:"type"`
	ClientEmail  string `json:"client_email"`
	PrivateKey   string `json:"private_key"`
	TokenURI     string `json:"token_uri"`
	PrivateKeyID string `json:"private_key_id"`
}

// GoogleWorkspaceProvider uses service-account Domain-Wide Delegation only. It never
// accepts interactive OAuth or refresh tokens and never logs the credential material.
type GoogleWorkspaceProvider struct {
	creds       googleServiceAccount
	admin       string
	http        httpDoer
	adminBase   string
	tokenSource oauth2.TokenSource
}

func NewGoogleWorkspaceProvider(serviceAccountJSON, delegatedAdminEmail string, doer httpDoer) (*GoogleWorkspaceProvider, error) {
	var creds googleServiceAccount
	if err := json.Unmarshal([]byte(serviceAccountJSON), &creds); err != nil {
		return nil, fmt.Errorf("google service-account JSON is invalid")
	}
	if creds.Type != "service_account" || creds.ClientEmail == "" || creds.PrivateKey == "" {
		return nil, fmt.Errorf("google service-account JSON must contain a service account client_email and private_key")
	}
	if !strings.Contains(delegatedAdminEmail, "@") {
		return nil, fmt.Errorf("delegated admin email is invalid")
	}
	key := &jwt.Config{Email: creds.ClientEmail, PrivateKey: []byte(creds.PrivateKey), PrivateKeyID: creds.PrivateKeyID, TokenURL: creds.TokenURI, Scopes: []string{adminDirectoryGroupsScope, adminDirectoryUsersScope}, Subject: delegatedAdminEmail}
	if key.TokenURL == "" {
		key.TokenURL = "https://oauth2.googleapis.com/token"
	}
	if doer == nil {
		doer = http.DefaultClient
	}
	return &GoogleWorkspaceProvider{creds: creds, admin: delegatedAdminEmail, http: doer, adminBase: "https://admin.googleapis.com/admin/directory/v1", tokenSource: key.TokenSource(context.Background())}, nil
}

func (g *GoogleWorkspaceProvider) get(ctx context.Context, path string) (*http.Response, error) {
	tok, err := g.tokenSource.Token()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.adminBase+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/json")
	return g.http.Do(req)
}

func (g *GoogleWorkspaceProvider) ListGroupMembers(ctx context.Context, groupID string) ([]DirectoryMember, error) {
	resp, err := g.get(ctx, "/groups/"+url.PathEscape(groupID)+"/members?includeDerivedMembership=true&roles=MEMBER&maxResults=200")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrGroupGone
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google list group members: status %d", resp.StatusCode)
	}
	var page struct {
		Members []struct{ ID, Email, Status string } `json:"members"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, err
	}
	out := make([]DirectoryMember, 0, len(page.Members))
	for _, m := range page.Members {
		st := StatusActive
		if strings.EqualFold(m.Status, "SUSPENDED") {
			st = StatusDisabled
		}
		out = append(out, DirectoryMember{ExternalID: m.ID, Email: strings.ToLower(m.Email), Status: st})
	}
	return out, nil
}

func (g *GoogleWorkspaceProvider) ResolveUserStatus(ctx context.Context, externalID string) (UserStatus, error) {
	resp, err := g.get(ctx, "/users/"+url.PathEscape(externalID)+"?projection=basic")
	if err != nil {
		return StatusActive, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return StatusGone, nil
	}
	if resp.StatusCode != http.StatusOK {
		return StatusActive, fmt.Errorf("google resolve user: status %d", resp.StatusCode)
	}
	var u struct {
		Suspended bool `json:"suspended"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return StatusActive, err
	}
	if u.Suspended {
		return StatusDisabled, nil
	}
	return StatusActive, nil
}
