// Package publicurl carries the installation's validated public address through
// one request. Only server configuration may populate it, never client headers.
package publicurl

import "context"

type key struct{}

func With(ctx context.Context, address string) context.Context {
	return context.WithValue(ctx, key{}, address)
}

func From(ctx context.Context, fallback string) string {
	if address, ok := ctx.Value(key{}).(string); ok && address != "" {
		return address
	}
	return fallback
}
