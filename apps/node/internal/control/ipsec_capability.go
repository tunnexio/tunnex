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

func (c *Client) ipsecRecoveryCapability() int {
	if c == nil {
		return 0
	}
	controller := c.ipsecController.Load()
	if controller == nil {
		return 0
	}
	return controller.RecoveryCapability()
}

// BGP support is reported only from the actual opaque qualified controller.
func (c *Client) ipsecBGPCapability() int {
	if c == nil {
		return 0
	}
	controller := c.ipsecController.Load()
	if controller == nil || controller.Capability() != 1 {
		return 0
	}
	return controller.BGPCapability()
}

// The provider capability identifies this reader, while native BGP/controller
// qualification still determines host readiness. It is not a cloud health claim.
func (c *Client) ipsecGCPHACapability() int {
	if c == nil {
		return 0
	}
	controller := c.ipsecController.Load()
	if controller == nil {
		return 0
	}
	return controller.GCPHACapability()
}

func (c *Client) ipsecGCPClassicCapability() int {
	if c == nil {
		return 0
	}
	controller := c.ipsecController.Load()
	if controller == nil {
		return 0
	}
	return controller.GCPClassicCapability()
}

func (c *Client) ipsecAzureCapability() int {
	if c == nil {
		return 0
	}
	controller := c.ipsecController.Load()
	if controller == nil {
		return 0
	}
	return controller.AzureCapability()
}

// Azure BGP retained recreation has a separate protocol qualification. Neither
// the provider reader nor static retained-guard support implies this capability.
func (c *Client) ipsecAzureBGPRecreationCapability() int {
	if c == nil {
		return 0
	}
	controller := c.ipsecController.Load()
	if controller == nil || controller.Capability() != 1 {
		return 0
	}
	return azureBGPRecreationVersion(controller)
}

// The optional method keeps old controllers explicitly unsupported. This helper
// is only reached with the actual opaque controller in the advertisement path.
func azureBGPRecreationVersion(controller any) int {
	qualified, ok := controller.(interface{ AzureBGPRecreationCapability() int })
	if !ok || qualified.AzureBGPRecreationCapability() != 1 {
		return 0
	}
	return 1
}
