//go:build !darwin && !windows

package helper

// collectPosture on unsupported platforms (CI/linux): every fact is
// indeterminate — reported absent upstream, never guessed.
func collectPosture() PostureStatus {
	return PostureStatus{}
}
