package http

// NewDeviceApprovalEdition reports whether the device-approval gate (S7.3 device posture)
// is available in this build. TRUE in the enterprise build. See the open-build twin for
// the named-per-feature rationale (F2 / S12.1).
func NewDeviceApprovalEdition() bool { return true }
