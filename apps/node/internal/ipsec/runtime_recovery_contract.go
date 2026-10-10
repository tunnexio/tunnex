package ipsec

// runtimeRecoveryContract recognizes wire intent only. It does not establish
// runtime support, grant authority, or enable recovery for a controller.
func runtimeRecoveryContract(m RuntimeManifest) (bool, error) {
	if m.RecoveryVersion == nil {
		return false, nil
	}
	if *m.RecoveryVersion != 1 || IsAzureRuntimeProfile(m.ProfileID) && m.ProfileID != AzureActiveActiveStaticProfile {
		return false, ErrRuntimeController
	}
	return true, nil
}
