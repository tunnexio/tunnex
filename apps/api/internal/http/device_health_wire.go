package http

// NewDeviceHealthEdition: the enterprise build unlocks device health / posture
// checks (S7.5.3). UNLOCK-THEN-OPT-IN: unlocking makes the feature AVAILABLE;
// every check stays org-level default-OFF until an admin opts in (no
// org_health_checks row = check off).
func NewDeviceHealthEdition() bool { return true }
