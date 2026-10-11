package bgp

import "errors"

// This wrapper retains the original error while exposing only a fixed clause.
type preflightRefusal struct {
	reason string
	cause  error
}

func (e *preflightRefusal) Error() string { return e.cause.Error() }
func (e *preflightRefusal) Unwrap() error { return e.cause }
func preflightRefused(reason string, cause error) error {
	return &preflightRefusal{reason: reason, cause: cause}
}

// PreflightRefusalReason never returns an error message, daemon output or suffix.
func PreflightRefusalReason(err error) string {
	var refusal *preflightRefusal
	if !errors.As(err, &refusal) {
		return "unclassified"
	}
	switch refusal.reason {
	case "children-identity", "children-listeners", "identity", "input", "missing-receipt", "observer-alive", "observer-close", "observer-listeners-recheck", "observer-rib", "observer-start", "package", "package-identity", "private-directory", "private-directory-remove", "private-parent-open", "private-parent-sync", "receipt-current", "routes-after-close", "routes-before", "routes-observed":
		return refusal.reason
	default:
		return "unclassified"
	}
}
