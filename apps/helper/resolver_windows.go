//go:build windows

package helper

import (
	"context"
	"os/exec"
	"time"
)

// nrptCmdTimeout bounds a single powershell.exe invocation so a wedged cmdlet can't hang the helper.
const nrptCmdTimeout = 15 * time.Second

// setResolvers is the Windows entry the Server dispatches VerbSetResolvers to (S8.4b): it reconciles the
// domain-scoped NRPT rules to the desired set via the documented PowerShell cmdlets. Same dispatch class
// as macOS set_resolvers — state-changing but NOT tunnel-owning: it never touches tunnel state, owner
// tracking, or the WFP kill-switch. resolvers_unsupported RETIRES on Windows here.
func setResolvers(desired []ResolverForward) error {
	return reconcileNRPT(psRun, desired)
}

// psRun runs one PowerShell -Command script (the cmdRunner binding). -NoProfile -NonInteractive matches the
// posture path (posture_windows.go) — no profile scripts, no prompts. Output() returns stdout; a non-zero
// exit or a stderr-bearing failure surfaces as err (wrapped into a typed nrpt_* ProtocolError upstream).
func psRun(script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nrptCmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx,
		"powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script,
	).Output()
	return string(out), err
}
