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

type addressTargetLookupKey struct{}

// WithAddressTargetLookup prevents address rewriting in optional target chains.
// Cache refreshes carry this policy explicitly without retaining client state.
func WithAddressTargetLookup(ctx context.Context) context.Context {
	return context.WithValue(ctx, addressTargetLookupKey{}, true)
}

func AddressTargetLookup(ctx context.Context) bool {
	v, _ := ctx.Value(addressTargetLookupKey{}).(bool)
	return v
}
