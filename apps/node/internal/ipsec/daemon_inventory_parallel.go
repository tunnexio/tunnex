package ipsec

import "context"

// The production constructor supplies a per-request owned VICI transport.
// Injected legacy request hooks stay serial unless an immutable test factory
// explicitly exercises this same read-only production mode.
func (c *DaemonClient) independentReadClient() *DaemonClient {
	return &DaemonClient{request: c.request, independentInspect: true}
}

// Version has already been read and validated. These independent read-only
// queries own their maps, connections and result buffers. Join every query
// before validation/return; no inventory survives this bounded observation.
func (c *DaemonClient) inspectIndependentInventory(ctx context.Context, daemon, release string) (DaemonInventory, error) {
	invalid := func() (DaemonInventory, error) { return DaemonInventory{}, ErrDaemonProtocol }
	if ctx.Err() != nil {
		return invalid()
	}
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type queryResult struct {
		index   int
		message viciMessage
		events  []viciMessage
		err     error
	}
	queries := []struct{ command, event string }{{"stats", ""}, {"get-algorithms", ""}, {"get-conns", ""}, {"get-shared", ""}, {"list-sas", "list-sa"}}
	completed := make(chan queryResult, len(queries))
	for index, query := range queries {
		go func(index int, command, event string) {
			message, events, err := c.request(readCtx, command, event, viciMessage{})
			completed <- queryResult{index, message, events, err}
		}(index, query.command, query.event)
	}
	results := make([]queryResult, len(queries))
	failed := false
	for range queries {
		result := <-completed
		results[result.index] = result
		if result.err != nil {
			failed = true
			cancel()
		}
	}
	if failed || ctx.Err() != nil {
		return invalid()
	}
	plugins, ok := viciStrings(results[0].message, "plugins")
	if !ok {
		return invalid()
	}
	for _, required := range []string{"vici", "kernel-netlink", "socket-default", "openssl", "random", "nonce", "kdf"} {
		if !containsString(plugins, required) {
			return invalid()
		}
	}
	if !verifyEngineAlgorithms(results[1].message) {
		return invalid()
	}
	identifiers := func(message viciMessage, key string) ([]string, error) {
		values, ok := viciStrings(message, key)
		if !ok {
			return nil, ErrDaemonProtocol
		}
		seen := map[string]bool{}
		for _, value := range values {
			if !validVICIName(value) || seen[value] {
				return nil, ErrDaemonProtocol
			}
			seen[value] = true
		}
		return values, nil
	}
	conns, err := identifiers(results[2].message, "conns")
	if err != nil {
		return invalid()
	}
	keys, err := identifiers(results[3].message, "keys")
	if err != nil {
		return invalid()
	}
	if len(results[4].message) != 0 {
		return invalid()
	}
	sas, err := parseDaemonSAs(results[4].events)
	if err != nil {
		return invalid()
	}
	if ctx.Err() != nil {
		return invalid()
	}
	return DaemonInventory{Daemon: daemon, Version: release, Plugins: plugins, Connections: conns, SharedKeys: keys, SAs: sas}, nil
}
