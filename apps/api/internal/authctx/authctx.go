// Package authctx carries the authenticated principal and the authorized org
// through the request context.
//
// Two invariants this package exists to enforce:
//   - The org used for tenant scoping is set ONLY here (WithOrg), and only after
//     membership authorization. Handlers/services never take an org id from a
//     request body or query string for scoping — that is the classic IDOR.
//   - No principal in context means unauthenticated: callers fail closed.
package authctx

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

// Principal is the authenticated caller and the orgs they belong to (with role).
// It is populated by the auth layer (a session-backed AuthFunc from S2); tests
// inject one directly.
// Auth methods a principal can be minted with. Stamped ONCE at the credential/session mint seam
// and IMMUTABLE for that principal's lifetime (session fixation: the method a session was born with
// never changes). The S7.5.5 MFA-enrollment gate keys on this so D5's exemptions hold at the
// middleware (SSO + bearer are exempt by construction, not by route/header sniffing). An empty
// method = a legacy session minted before the marker existed; it is treated as NON-local (exempt),
// which aligns with D8 (enforcement governs new LOGINS, not live sessions — legacy sessions age out).
const (
	AuthLocalPassword = "local_password"
	AuthSSO           = "sso"
	AuthBearer        = "bearer"
	// AuthMachine (S10.2) — a NON-USER machine credential (the GitOps operator). Exempt from the
	// MFA-enrollment gate by construction (no human, no enrollment), like AuthBearer. A machine principal
	// has UserID == uuid.Nil and MachineID/MachineName set; its mutations attribute to a SYSTEM actor.
	AuthMachine = "machine"
	// AuthAgent (S15.2, D4) — a data-plane AGENT, authenticated by mTLS client certificate rather than by
	// a bearer token.
	//
	// ⛔ A SECOND NON-HUMAN PRINCIPAL KIND, AND IT IS NOT AuthMachine WEARING A HAT. A machine credential is
	// a bearer secret an operator mints and can revoke by deleting a row; an agent is a certificate the CA
	// issued to a gateway that is carrying traffic right now. They differ in how they authenticate, in what
	// revoking them costs, and in what a refusal breaks — a pipeline versus a tunnel. Collapsing them would
	// make D25's whole ruling unstatable.
	AuthAgent = "agent"
)

type Principal struct {
	UserID        uuid.UUID
	SessionID     string // the session backing this principal (for logout)
	Email         string
	EmailVerified bool
	AuthMethod    string               // how this principal authenticated (AuthLocalPassword | AuthSSO | AuthBearer | AuthMachine | "")
	Roles         map[uuid.UUID]string // orgID -> role
	// ⛔ MustChangePassword — the CP admin's bootstrap credential was PRINTED TO LOGS, so it is treated as
	// compromised from the moment it works. Until it is changed the principal may authenticate and may do
	// NOTHING ELSE.
	MustChangePassword bool
	// ⛔ CPAdmin — the deployment-level capability. On the Principal because /auth/me rehydrates the
	// SPA from it on every page load, and a field the session cannot carry is a field that vanishes on
	// refresh.
	CPAdmin bool
	// MachineID / MachineName (S10.2) — set ONLY for a machine principal (AuthMachine); zero for a human.
	// A machine has NO UserID (kept out of the identity-binding subject space, D4). MachineName is the
	// operator-chosen credential label surfaced in audit as the system actor "operator:<name>".
	MachineID   uuid.UUID
	MachineName string
	// OwnerUserID (S15.1, D14) — the HUMAN a machine principal acts for. Set ONLY for a machine principal.
	//
	// ⛔ EVERY MACHINE PRINCIPAL SHIPPED BEFORE S15.1 WAS OWNERLESS, and that is what D14 ruled against: an
	// ownerless agent is outside the per-user device cap (which keys on user_id), outside any delegation
	// link, and still inside the org address pool — it costs the scarce thing and escapes both accountable
	// ones. This field is the delegation link the audit layer never had: `actor_user_id` and `actor_system`
	// are PARALLEL columns, so an event could be attributed to a human OR a subsystem, never "this system
	// acting for that human".
	//
	// ⚠ It is NOT part of the identity-binding subject space — a machine still has no UserID, and D4's
	// separation stands. This says whose accountability the credential rides on, not who it authenticates as.
	OwnerUserID uuid.UUID
	// NodeID / NodeName (S15.2, D4) — set ONLY for an agent principal (AuthAgent); zero for everything else.
	//
	// ⛔ A DISTINCT FIELD, NOT A REUSE OF MachineID, AND THE CENSUS IS THE REASON. The S15.0 census licensed
	// a constructor because `MachineID` had exactly ONE construction site. Overloading that field would make
	// the census's own sentence ambiguous — "one construction site" would silently mean two principal kinds
	// — and the guarantee it stood for (a non-human principal cannot be built without passing through the
	// place that enforces ownership) would be true of neither. A separate field keeps each census honest.
	NodeID   uuid.UUID
	NodeName string
	// Cause (S10.2 Slice 4, D2) — a machine-only, per-request OVERRIDE for the audit cause: the CR that drove
	// the change (e.g. "tunnexcluster:default/prod"). Set ONLY from the X-Tunnex-Cause header on a machine
	// principal (a human's principal never carries it), sanitized. Empty → AuditActor falls back to the
	// credential identity. This is what makes a cascade delete name the CR, not just the operator (D2 cond 2).
	Cause string
}

// NewMachinePrincipal is the ONLY way to build a machine-bearing Principal (S15.1).
//
// ⛔ THE OWNER IS A REQUIRED ARGUMENT, AND THAT IS THE WHOLE POINT. Principal is a struct literal, so every
// field is optional by construction — which is exactly how `policyHealthBadge` came to be structurally
// forbidden from forming the verdict it was named for, and why its revoked guard ended up copy-pasted into
// callers instead of living in the callee. **A guard enforced by types beats one enforced by discipline**, and
// this constructor was taken at the one moment it was available: before the field existed anywhere.
//
// ⚠ THE CENSUS IS WHAT LICENSED IT, NOT THE PATTERN. Measured by INPUT rather than by caller: `MachineID` has
// exactly ONE construction site (http/machine_bearer.go) and `machine_credentials` has exactly ONE
// authenticating query (GetMachineCredentialByHash). No second door — so a constructor is necessary AND
// sufficient here. For `policyHealthBadge` it was neither: seven sites, four wrong, two of which never called
// the function at all because they read the field raw. **Anyone reaching for a constructor must run that
// census first; more than one door means necessary and NOT sufficient.**
//
// Returns nil when the owner is absent. A nil principal is an unauthenticated request at the seam — the same
// shape the four existing fail-closed arms already return, so a NULL owner is refused exactly where a revoked
// credential is, with no oracle distinguishing them.
func NewMachinePrincipal(ownerUserID, machineID, orgID uuid.UUID, machineName, role, cause string) *Principal {
	if ownerUserID == uuid.Nil || machineID == uuid.Nil {
		return nil
	}
	return &Principal{
		MachineID:   machineID,
		MachineName: machineName,
		OwnerUserID: ownerUserID,
		AuthMethod:  AuthMachine,
		Roles:       map[uuid.UUID]string{orgID: role},
		Cause:       cause,
	}
}

// IsMachine reports whether this is a non-user machine principal (S10.2).
func (p *Principal) IsMachine() bool { return p != nil && p.MachineID != uuid.Nil }

// AuditActor returns the attribution for an audited mutation. For a HUMAN: (userID, "", "") → the row is
// actor_user_id-attributed (system + cause empty). For a MACHINE: (uuid.Nil, "operator:<name>",
// "machine_credential:<id>") → a SYSTEM-actor row (actor_system, migration 0027) whose cause names the
// machine credential. This is the ONE seam that keeps a GitOps change from masquerading as a human (D3 — a
// falsely-attributed row is worse than absent). If the machine set a per-request Cause (the CR that drove the
// change, via X-Tunnex-Cause, D2 Slice 4), that names the WHY; the credential identity is the honest default.
func (p *Principal) AuditActor() (actorUserID uuid.UUID, actorSystem, cause string) {
	if p.IsMachine() {
		cause = "machine_credential:" + p.MachineID.String()
		if p.Cause != "" {
			cause = p.Cause // the CR the operator names as the cause (D2 cond 2)
		}
		return uuid.Nil, "operator:" + p.MachineName, cause
	}
	return p.UserID, "", ""
}

// SanitizeCause bounds an operator-supplied audit cause (X-Tunnex-Cause): control characters stripped (no
// audit-log injection / newline forgery) and length capped. Untrusted machine input lands in the audit cause
// column, so it is cleaned at the seam, never trusted raw.
func SanitizeCause(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f { // drop control chars incl CR/LF/TAB
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 200 {
			break
		}
	}
	return b.String()
}

// RoleIn returns the principal's role in orgID and whether they are a member.
func (p *Principal) RoleIn(orgID uuid.UUID) (string, bool) {
	if p == nil {
		return "", false
	}
	r, ok := p.Roles[orgID]
	return r, ok
}

type ctxKey int

const (
	principalKey ctxKey = iota
	orgKey
)

// WithPrincipal attaches the authenticated principal.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalFrom returns the principal, or ok=false if unauthenticated.
func PrincipalFrom(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey).(*Principal)
	return p, ok && p != nil
}

// WithOrg records the AUTHORIZED org for tenant scoping. Call only after a
// membership check — never from client-supplied input.
func WithOrg(ctx context.Context, orgID uuid.UUID) context.Context {
	return context.WithValue(ctx, orgKey, orgID)
}

// OrgFrom returns the authorized org id set by the tenant authorization step.
func OrgFrom(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(orgKey).(uuid.UUID)
	return id, ok
}

// NewAgentPrincipal builds the principal for a data-plane agent (S15.2, D4 — RULED: a SECOND constructor).
//
// ⛔ THE SECOND CONSTRUCTOR RETIRES THE OLD CENSUS'S GUARANTEE, AND SAYS SO RATHER THAN INHERITING IT.
//
// The S15.0 census found `MachineID` had exactly one construction site, which is why a constructor was
// licensed there instead of a per-handler guard. That sentence stays literally true — an agent carries
// `NodeID`, not `MachineID` — and **the guarantee it stood for does not transfer**, because the guarantee
// was never about `MachineID`. It was: *a non-human principal cannot be built without passing through the
// one place that enforces ownership.* A second kind has its own doorway.
//
// > **A CENSUS IS A STATEMENT ABOUT A MOMENT AND IT IS NOT SELF-RENEWING.** What replaces the old guarantee
// > is a NEW census, by INPUT, over `NodeID` — run as a merge gate, not as a review note. See
// > `agent_principal_census_test.go`, which fails if a second construction site appears.
//
// ⚠ NO OWNER IS REQUIRED, AND THAT IS D25(C), NOT AN OVERSIGHT. An agent with no owner is UNATTRIBUTABLE
// and still runs: the policy engine enforces every rule regardless, so refusing here would drop a tunnel
// for an identity-management reason and buy nothing. Contrast NewMachinePrincipal, which returns nil for a
// nil owner — a refused GitOps operator fails a pipeline, and that is a cost worth paying.
func NewAgentPrincipal(nodeID, orgID uuid.UUID, nodeName, role string, ownerUserID uuid.UUID, cause string) *Principal {
	if nodeID == uuid.Nil || orgID == uuid.Nil {
		return nil
	}
	return &Principal{
		NodeID:      nodeID,
		NodeName:    nodeName,
		OwnerUserID: ownerUserID, // uuid.Nil for an unattributable agent — see D25(C) above
		AuthMethod:  AuthAgent,
		Roles:       map[uuid.UUID]string{orgID: role},
		Cause:       cause,
	}
}

// IsAgent reports whether this principal is a data-plane agent.
//
// ⚠ KEYED ON AuthMethod, NOT ON A NON-ZERO NodeID. A field being set is a symptom; the auth method is the
// fact. Reading the field would make any future code that populates NodeID for another reason silently
// become an agent.
func (p *Principal) IsAgent() bool { return p != nil && p.AuthMethod == AuthAgent }

// Unattributable reports that this principal's actions cannot be tied to a person (S15.2, D25(C)).
//
// ⛔ TRUE IS A STATEMENT ABOUT THE AUDIT TRAIL, NEVER ABOUT PERMISSION. An unattributable agent is not
// less authorized — the policy engine enforces every rule identically. Any caller that branches on this to
// DENY something has misread it.
func (p *Principal) Unattributable() bool {
	return p.IsAgent() && p.OwnerUserID == uuid.Nil
}
