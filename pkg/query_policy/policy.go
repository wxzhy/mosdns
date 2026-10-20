// Package query_policy carries internal, opt-in transport policies for selector
// branches. Ordinary forward queries retain their historical transport lifetime.
package query_policy

import "context"

type inheritCancellationKey struct{}

func WithInheritedCancellation(ctx context.Context) context.Context {
	return context.WithValue(ctx, inheritCancellationKey{}, true)
}

func InheritCancellation(ctx context.Context) bool {
	v, _ := ctx.Value(inheritCancellationKey{}).(bool)
	return v
}
