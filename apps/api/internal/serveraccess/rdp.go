package serveraccess

import (
	"encoding/json"
	"errors"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/packages/apptransport/rdpwire"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
)

func validateBrowserFrame(server api.ServerAccessServer, account string, f terminalwire.Frame) error {
	if serverOS(server) != "windows" {
		return f.ValidateInput()
	}
	if f.Rows != 0 || f.Cols != 0 || f.Reason != "" || len(f.Data) == 0 || len(f.Data) > terminalwire.MaxDataBytes {
		return errors.New("invalid desktop frame")
	}
	if f.Type == "clipboard" {
		return rdpwire.ValidateClipboardPaste(serverClipboardPolicy(server), f.Data)
	}
	if f.Type == "credentials" {
		var c rdpwire.Credentials
		if json.Unmarshal(f.Data, &c) != nil || c.Account != account || len(c.Password) == 0 || len(c.Password) > 1024 {
			return errors.New("invalid RDP credentials")
		}
		return nil
	}
	if f.Type != "desktop" {
		return errors.New("unsupported desktop frame")
	}
	return rdpwire.ValidateInput(f.Data)
}
