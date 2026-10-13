package control

// This compatibility signal comes only from the current opaque qualified
// controller. Missing/unqualified runtime explicitly withdraws support.
func (c *Client) ipsecRetainedGuardCapability() int {
	if c == nil {
		return 0
	}
	controller := c.ipsecController.Load()
	if controller == nil || controller.Capability() != 1 {
		return 0
	}
	return controller.RetainedGuardCapability()
}
