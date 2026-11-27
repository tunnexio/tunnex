package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

// The MCP gateway calls (AI-SEC-2) ride the node mTLS channel: the control plane takes the organization
// and the node from the client certificate. Errors never carry a response body, because a decision and a
// target list can hold a credential.

// mcpDo sends one request without following redirects: the evidence headers and the request body go to
// the authenticated control endpoint and nowhere else.
func (c *Client) mcpDo(ctx context.Context, method, path string, body any, headers map[string]string) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	client := *c.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client.Do(req)
}

func mcpEvidence(vpnIP, vpnKey string) map[string]string {
	return map[string]string{mcpwire.HeaderVPNIP: vpnIP, mcpwire.HeaderVPNKey: vpnKey}
}

// MCPDecide asks the control plane whether the peer the gateway observed (tunnel source address and
// WireGuard key) may make this MCP request. Any error means no decision, which the caller must treat as a
// denial. An allow is accepted only with HTTP 200; a well-formed deny is accepted with any status.
func (c *Client) MCPDecide(ctx context.Context, vpnIP, vpnKey string, request mcpwire.DecideRequest) (mcpwire.DecideResponse, error) {
	resp, err := c.mcpDo(ctx, http.MethodPost, mcpwire.PathDecide, request, mcpEvidence(vpnIP, vpnKey))
	if err != nil {
		return mcpwire.DecideResponse{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return mcpwire.DecideResponse{}, fmt.Errorf("MCP decision unreadable (status %d)", resp.StatusCode)
	}
	var decision mcpwire.DecideResponse
	decoded := json.Unmarshal(data, &decision) == nil
	if resp.StatusCode != http.StatusOK {
		if decoded && decision.Decision == mcpwire.DecisionDeny && decision.Valid() == nil {
			return decision, nil
		}
		return mcpwire.DecideResponse{}, fmt.Errorf("MCP decision status %d", resp.StatusCode)
	}
	if !decoded || decision.Valid() != nil {
		return mcpwire.DecideResponse{}, mcpwire.ErrInvalidDecision
	}
	return decision, nil
}

// MCPResult closes an allowed call's activity row with what happened upstream.
func (c *Client) MCPResult(ctx context.Context, vpnIP, vpnKey string, result mcpwire.ResultRequest) error {
	return c.mcpReport(ctx, mcpwire.PathResult, result, mcpEvidence(vpnIP, vpnKey))
}

// MCPInventory reports what the gateway observed on one agent's MCP server: raw definitions, no hashes.
func (c *Client) MCPInventory(ctx context.Context, report mcpwire.InventoryReport) error {
	return c.mcpReport(ctx, mcpwire.PathInventory, report, nil)
}

func (c *Client) mcpReport(ctx context.Context, path string, body any, headers map[string]string) error {
	resp, err := c.mcpDo(ctx, http.MethodPost, path, body, headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("%s status %d", path, resp.StatusCode)
	}
	return nil
}

// MCPTargets lists the agents homed on this gateway whose MCP server it discovers.
func (c *Client) MCPTargets(ctx context.Context) ([]mcpwire.Target, error) {
	resp, err := c.mcpDo(ctx, http.MethodGet, mcpwire.PathTargets, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return nil, fmt.Errorf("%s status %d", mcpwire.PathTargets, resp.StatusCode)
	}
	var out mcpwire.TargetsResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("%s response is invalid", mcpwire.PathTargets)
	}
	return out.Targets, nil
}
