package idpsync

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sso"
)

// OktaProvider reads the directory with a dedicated scoped OAuth service app.
// Credential and response bodies never become operator-facing errors.
type OktaProvider struct {
	origin, clientID string
	key              jose.JSONWebKey
	http             httpDoer
	now              func() time.Time
	mu               sync.Mutex
	token            string
	expiry           time.Time
}

func ValidateOktaOrigin(raw string) error {
	if err := sso.ValidateCustomIssuer(raw); err != nil {
		return err
	}
	u, _ := url.Parse(raw)
	if u.Path != "" || u.RawPath != "" {
		return errors.New("Okta organization URL must be an HTTPS origin without an authorization-server path")
	}
	return nil
}

func NewOktaProvider(origin, clientID, privateJWK string, doer httpDoer) (*OktaProvider, error) {
	if err := ValidateOktaOrigin(origin); err != nil {
		return nil, err
	}
	var key jose.JSONWebKey
	if len(privateJWK) > 16384 || json.Unmarshal([]byte(privateJWK), &key) != nil || !key.Valid() || key.KeyID == "" {
		return nil, errors.New("Okta requires a valid RSA private JWK with a key ID")
	}
	rsaKey, ok := key.Key.(*rsa.PrivateKey)
	if !ok || rsaKey.N.BitLen() < 2048 || rsaKey.Validate() != nil || (key.Algorithm != "" && key.Algorithm != "RS256") || (key.Use != "" && key.Use != "sig") {
		return nil, errors.New("Okta signing key must be RSA 2048-bit or stronger with RS256")
	}
	if strings.TrimSpace(clientID) == "" {
		return nil, errors.New("Okta service app client ID is required")
	}
	if doer == nil {
		doer = sso.NewPublicProviderHTTPClient()
	}
	return &OktaProvider{origin: origin, clientID: clientID, key: key, http: doer, now: time.Now}, nil
}

func (p *OktaProvider) bearer(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if p.token != "" && now.Add(30*time.Second).Before(p.expiry) {
		return p.token, nil
	}
	endpoint := p.origin + "/oauth2/v1/token"
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", errors.New("Okta assertion signing failed")
	}
	assertion, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: p.clientID, Subject: p.clientID, Audience: jwt.Audience{endpoint}, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(5 * time.Minute)), ID: uuid.NewString()}).Serialize()
	if err != nil {
		return "", errors.New("Okta assertion signing failed")
	}
	body := url.Values{"grant_type": {"client_credentials"}, "scope": {"okta.users.read okta.groups.read"}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.http.Do(req)
	if err != nil {
		return "", errors.New("Okta token request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Okta token request: HTTP %d", resp.StatusCode)
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if decodeOkta(resp.Body, &token) != nil || token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") || token.ExpiresIn <= 0 || token.ExpiresIn > 86400 {
		return "", errors.New("Okta token response is invalid")
	}
	p.token = token.AccessToken
	p.expiry = now.Add(time.Duration(token.ExpiresIn) * time.Second)
	return p.token, nil
}
func decodeOkta(r io.Reader, out any) error {
	raw, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return errors.New("Okta response exceeds limit or is unreadable")
	}
	if json.Unmarshal(raw, out) != nil {
		return errors.New("Okta response is malformed")
	}
	return nil
}
func (p *OktaProvider) get(ctx context.Context, endpoint string) (*http.Response, error) {
	token, err := p.bearer(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New("invalid Okta request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, errors.New("Okta directory request failed")
	}
	return resp, nil
}

type oktaUser struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Profile struct {
		Email string `json:"email"`
	} `json:"profile"`
}

func oktaStatus(s string) (UserStatus, error) {
	switch s {
	case "ACTIVE":
		return StatusActive, nil
	case "SUSPENDED", "DEPROVISIONED":
		return StatusDisabled, nil
	default:
		return StatusActive, errors.New("Okta user lifecycle state is not supported; membership retained until it can be resolved")
	}
}
func oktaID(id string) bool {
	if len(id) < 3 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
func (p *OktaProvider) ListGroupMembers(ctx context.Context, groupID string) ([]DirectoryMember, error) {
	if !oktaID(groupID) {
		return nil, errors.New("invalid Okta group ID")
	}
	path := "/api/v1/groups/" + groupID + "/users"
	next := p.origin + path + "?limit=200"
	seen := map[string]bool{}
	users := map[string]bool{}
	out := []DirectoryMember{}
	for page := 0; next != ""; page++ {
		if page >= 1000 || seen[next] {
			return nil, errors.New("Okta pagination limit or cycle")
		}
		seen[next] = true
		resp, err := p.get(ctx, next)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			if page == 0 && resp.StatusCode == 404 {
				return nil, ErrGroupGone
			}
			return nil, fmt.Errorf("Okta group read: HTTP %d", resp.StatusCode)
		}
		var batch []oktaUser
		err = decodeOkta(resp.Body, &batch)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if batch == nil {
			return nil, errors.New("Okta member collection is invalid")
		}
		for _, u := range batch {
			st, e := oktaStatus(u.Status)
			if e != nil {
				return nil, e
			}
			if !oktaID(u.ID) || strings.TrimSpace(u.Profile.Email) == "" || users[u.ID] {
				return nil, errors.New("Okta member identity is invalid or duplicated")
			}
			users[u.ID] = true
			out = append(out, DirectoryMember{ExternalID: u.ID, Email: strings.ToLower(u.Profile.Email), Status: st})
		}
		next, err = p.nextPage(resp.Header.Values("Link"), path)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (p *OktaProvider) nextPage(headers []string, path string) (string, error) {
	next := ""
	for _, header := range headers {
		for _, part := range strings.Split(header, ",") {
			bits := strings.Split(part, ";")
			isNext, hasRelation := false, false
			for _, param := range bits[1:] {
				name, value, ok := strings.Cut(strings.TrimSpace(param), "=")
				if !ok || strings.TrimSpace(name) != "rel" {
					continue
				}
				if hasRelation {
					return "", errors.New("ambiguous Okta pagination relation")
				}
				hasRelation = true
				value = strings.TrimSpace(value)
				if strings.HasPrefix(value, `"`) != strings.HasSuffix(value, `"`) {
					return "", errors.New("invalid Okta pagination relation")
				}
				for _, rel := range strings.Fields(strings.Trim(value, `"`)) {
					if rel == "next" {
						isNext = true
					}
				}
			}
			if !hasRelation {
				return "", errors.New("missing Okta pagination relation")
			}
			if !isNext {
				continue
			}
			raw := strings.TrimSpace(bits[0])
			if !strings.HasPrefix(raw, "<") || !strings.HasSuffix(raw, ">") || next != "" {
				return "", errors.New("Okta pagination link is invalid")
			}
			u, err := url.Parse(raw[1 : len(raw)-1])
			if err != nil || u.Scheme+"://"+u.Host != p.origin || u.Path != path || u.RawPath != "" || u.User != nil || u.Fragment != "" {
				return "", errors.New("Okta pagination left the authorized collection")
			}
			next = u.String()
		}
	}
	return next, nil
}
func (p *OktaProvider) ResolveUserStatus(ctx context.Context, id string) (UserStatus, error) {
	if !oktaID(id) {
		return StatusActive, errors.New("invalid Okta user ID")
	}
	resp, err := p.get(ctx, p.origin+"/api/v1/users/"+id)
	if err != nil {
		return StatusActive, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return StatusGone, nil
	}
	if resp.StatusCode != 200 {
		return StatusActive, fmt.Errorf("Okta user read: HTTP %d", resp.StatusCode)
	}
	var u oktaUser
	if err = decodeOkta(resp.Body, &u); err != nil {
		return StatusActive, err
	}
	if u.ID != id {
		return StatusActive, errors.New("Okta user ID mismatch")
	}
	return oktaStatus(u.Status)
}
