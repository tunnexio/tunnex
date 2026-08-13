// Package sso implements SSO/OIDC login. It exists only in the enterprise build
// (`-tags enterprise`); the open build ships stub handlers that return a clean
// edition_required envelope.
//
// The design is a provider ABSTRACTION: Google is the first registration, and
// Microsoft (S2.4) is expected to be config + a small adapter, not a second
// implementation. The claims-normalization seam (Identity) is where every
// provider's token maps into one internal shape.
package sso

// Identity is the normalized result of a verified SSO login — the single shape
// downstream code consumes regardless of provider.
type Identity struct {
	Provider      string
	Subject       string // stable IdP user id (the OIDC "sub")
	Email         string
	EmailVerified bool
	Name          string
}

// LinkAction is the decision for reconciling an SSO Identity with local accounts.
type LinkAction int

const (
	// LinkReject: refuse and point the user at the interactive link flow.
	LinkReject LinkAction = iota
	// LinkCreate: no local account — provision one (JIT).
	LinkCreate
	// LinkAttach: a verified local account exists — link the SSO identity to it.
	LinkAttach
)

func (a LinkAction) String() string {
	switch a {
	case LinkCreate:
		return "create"
	case LinkAttach:
		return "attach"
	default:
		return "reject"
	}
}

// DecideLink is the account-linking policy. The dangerous path it must forbid is
// binding an SSO identity to an UNVERIFIED local account (account takeover via
// pre-registration), and trusting an UNVERIFIED IdP email at all.
//
//   - IdP email not verified            -> reject (never trust it).
//   - No local account                  -> create (JIT provisioning).
//   - Local account, verified           -> attach (safe auto-link).
//   - Local account, NOT verified       -> reject (require interactive link).
func DecideLink(localExists, localVerified, idpVerified bool) LinkAction {
	if !idpVerified {
		return LinkReject
	}
	if !localExists {
		return LinkCreate
	}
	if localVerified {
		return LinkAttach
	}
	return LinkReject
}
