package control

import "github.com/tunnexio/tunnex/apps/node/internal/ipsec"

// AttachIPsecController accepts only the actual controller, never an integer,
// environment flag or caller-supplied capability callback.
func (c *Client) AttachIPsecController(controller *ipsec.RuntimeController) {
	c.ipsecController.Store(controller)
}
func (c *Client) ipsecCapability() int {
	if c == nil {
		return 0
	}
	controller := c.ipsecController.Load()
	if controller == nil || controller.Capability() != 1 {
		return 0
	}
	return 1
}
