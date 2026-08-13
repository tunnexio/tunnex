package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/tunnexio/tunnex/apps/cli/internal/api"
)

// CreateDevice creates a device and captures its ONE-TIME config (D2: the
// config is served exactly once at creation and is never re-fetchable, so the
// CLI owns creation and writes atomically 0600 in the same breath).
func CreateDevice(ctx context.Context, name string, fullTunnel bool) error {
	cred, err := LoadActiveCredential()
	if err != nil {
		return err
	}
	client, err := NewAuthedClient(cred)
	if err != nil {
		return err
	}

	orgs, err := client.ListOrganizationsWithResponse(ctx)
	if err != nil {
		return err
	}
	if orgs.JSON200 == nil {
		return apiErr(orgs.StatusCode(), orgs.Body, "could not list organizations")
	}
	if len(*orgs.JSON200) == 0 {
		return errors.New("you are not a member of any organization yet")
	}
	org := (*orgs.JSON200)[0]

	nodes, err := client.ListNodesWithResponse(ctx, org.Id)
	if err != nil {
		return err
	}
	if nodes.JSON200 == nil {
		return apiErr(nodes.StatusCode(), nodes.Body, "could not list gateways")
	}
	var nodeID *api.Node
	for i, n := range *nodes.JSON200 {
		if n.Status == "active" {
			nodeID = &(*nodes.JSON200)[i]
			break
		}
	}
	if nodeID == nil {
		return errors.New("no active gateway is enrolled — enroll a tunnex-node agent first")
	}

	resp, err := client.CreateDeviceWithResponse(ctx, org.Id, api.CreateDeviceJSONRequestBody{
		Name: name, NodeId: nodeID.Id, FullTunnel: &fullTunnel,
	})
	if err != nil {
		return err
	}
	if resp.JSON201 == nil {
		return apiErr(resp.StatusCode(), resp.Body, "could not create the device")
	}
	if resp.JSON201.Config == nil || *resp.JSON201.Config == "" {
		return errors.New("the server returned no config (it is only served at creation)")
	}

	path, err := ConfigPath()
	if err != nil {
		return err
	}
	// Atomic + 0600: the private key is never on disk partially written or
	// world-readable, and it cannot be fetched again.
	if err := WriteFileAtomic0600(path, []byte(*resp.JSON201.Config)); err != nil {
		return fmt.Errorf("device created but the config could not be saved (it is NOT retrievable again — revoke device %q and retry): %w",
			resp.JSON201.Device.Id, err)
	}
	fmt.Printf("Device %q created on %q. Config written to %s (0600).\nBring it up with: tunnex up\n",
		name, nodeID.Name, path)
	return nil
}
