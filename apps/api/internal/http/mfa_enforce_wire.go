package http

// NewMfaEnforceEdition: the enterprise build unlocks ORG-LEVEL MFA enforcement (S7.5.5).
// UNLOCK-THEN-OPT-IN: unlocking makes the enforce toggle available; it stays org-level
// default-OFF (no org_mfa row = off) until an admin opts in. Enrollment itself is OPEN
// (all editions) — only the mandate + admin surface is enterprise. Also the downgrade-release
// seam (D2): in the open build this returns false, so enforcement RELEASES on downgrade while
// enrolled secrets are RETAINED (self-service enrollment keeps working).
func NewMfaEnforceEdition() bool { return true }
