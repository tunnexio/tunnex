package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// WgQuick shells out to wg-quick with the stored device config. Root (or the
// platform's equivalent) is wg-quick's requirement, not ours — its own error
// is surfaced verbatim.
func WgQuick(action string) error {
	if action != "up" && action != "down" {
		return fmt.Errorf("unsupported action %q", action)
	}
	path, err := ConfigPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return errors.New("no device config found — run 'tunnex device create --name <name>' first")
	}
	if _, err := exec.LookPath("wg-quick"); err != nil {
		return errors.New("wg-quick not found — install wireguard-tools")
	}
	cmd := exec.Command("wg-quick", action, path)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}
